// Copyright (c) 2026 The Dilithion Core developers
// Distributed under the MIT software license
//
// vdf-history-check — replay the LP-10 VDF consensus checks over stored blocks.
//
// WHY THIS EXISTS. `vdfProofEnforcementHeight` activates a consensus check every
// DilV block must then satisfy: a verifying Wesolowski proof AND a valid
// coinbase MIK signature. Every DilV block is a VDF block, so if blocks being
// mined today would NOT pass, pinning any height HALTS the chain there. RPC
// cannot answer it — `getblock` exposes no vdfOutput, no vdfProofHash, no raw
// hex and no coinbase scriptSig, and the proof lives in the scriptSig. It must
// be replayed against stored blocks on a binary containing the checkers.
//
// ⚠️ THIS IS A DECISION INSTRUMENT FOR A HARD FORK. A wrong answer either halts
// a live chain or waves through a broken activation. It is therefore built to
// refuse rather than to guess, and every claim it prints is gated on evidence
// produced in the same run. Each of the following exists because the FIRST
// version of this tool got it wrong:
//
//   * TWO INDEPENDENT MUTATION CONTROLS, one per checker. Two checkers with a
//     single control is how v1 reported the MIK arm "passing" when that arm had
//     silently fail-opened on every reference-MIK block.
//   * THE PROBE IS A BLOCK THAT PASSED CLEAN. A control firing on a block that
//     was already failing proves nothing — v1 sampled genesis, which fails for
//     an unrelated reason, so its control would have fired with the verifier
//     stubbed out.
//   * WALK COMPLETENESS IS ASSERTED, not eyeballed. v1 printed the chain length
//     and the tip height adjacently and compared them nowhere, so a silent
//     mid-walk break could still print ALL PASS and exit 0.
//   * THE NETWORK IS BOUND TO THE DATA by genesis hash: a wrong `--network`
//     changes vdfIterations, fails every block, and looks exactly like a
//     genuine consensus break.
//
// Genesis is EXEMPT by construction, not a failure: its coinbase output is a
// bare OP_RETURN, so no miner address can be extracted and no VDF challenge can
// be reconstructed. v1 reported it as a consensus failure — a cry-wolf on the
// one instrument whose alarm has to be believed.

#include <consensus/vdf_validation.h>
#include <core/chainparams.h>
#include <crypto/sha3.h>
#include <dfmp/dfmp.h>
#include <dfmp/mik.h>
#include <node/blockchain_storage.h>
#include <node/block_index.h>
#include <node/genesis.h>
#include <primitives/block.h>
#include <vdf/coinbase_vdf.h>
#include <vdf/vdf.h>

#include <algorithm>
#include <array>
#include <chrono>
#include <cstdint>
#include <cstring>
#include <filesystem>
#include <iostream>
#include <map>
#include <sstream>
#include <stdexcept>
#include <string>
#include <vector>

namespace {

void Usage()
{
    std::cout <<
        "vdf-history-check — replay LP-10 VDF checks over stored blocks\n\n"
        "  --datadir <path>     NODE datadir (contains blocks/ and dfmp_identity/)\n"
        "  --blocksdir <path>   block DB directly, when only blocks/ is available\n"
        "  --identitydb <path>  datadir holding dfmp_identity/ (default: --datadir)\n"
        "  --network <n>        dilv | mainnet | testnet | regtest   (default dilv)\n"
        "  --from <height>      first height to check (default 1; genesis is exempt)\n"
        "  --to <height>        last height to check (default: chain tip)\n"
        "  --verbose            print every failing height\n"
        "  --selftest           prove this binary detects forgeries, then exit\n\n"
        "WITHOUT an identity DB the MIK-signature checker FAILS OPEN on every\n"
        "reference-MIK block, so that half is reported UNMEASURED rather than as\n"
        "passing. Point --datadir at a real node datadir to measure it.\n\n"
        "The node using the datadir must be STOPPED: leveldb holds an exclusive\n"
        "lock, and a copy taken from a running node is torn.\n\n"
        "Exit: 0 every checked block passed AND both controls fired AND the walk\n"
        "        was complete; 1 failures found; 2 the run cannot be trusted.\n";
}

struct Ctx {
    std::string network = "dilv";
    bool identityDbOpen = false;
    bool checkGenesis   = true;   // false for the synthetic self-test fixture
};

bool InstallParams(const std::string& network)
{
    using Dilithion::ChainParams;
    ChainParams p;
    if      (network == "dilv")    p = ChainParams::DilV();
    else if (network == "mainnet") p = ChainParams::Mainnet();
    else if (network == "testnet") p = ChainParams::Testnet();
    else if (network == "regtest") p = ChainParams::Regtest();
    else return false;

    if (Dilithion::g_chainParams == nullptr) Dilithion::g_chainParams = new ChainParams(p);
    else                                     *Dilithion::g_chainParams = p;

    // FORCE THE ACTIVATION GATE OPEN so every block is truly checked. With the
    // shipped 999999999 sentinel this tool would report a flawless chain while
    // verifying nothing — the vacuous green it exists to prevent.
    Dilithion::g_chainParams->vdfProofEnforcementHeight = 0;
    return true;
}

struct Failure {
    int         height;
    std::string what;
    std::string detail;
};

struct ScanResult {
    bool      opened       = false;
    bool      walkComplete = false;   // contiguous genesis..tip, ASSERTED
    bool      genesisMatch = false;   // the data really is this --network
    bool      proofControl = false;   // corrupting vdfOutput was rejected
    bool      mikControl   = false;   // corrupting the MIK signature was rejected
    // A control that cannot fire is not the same as a checker that is not live.
    // Conflating them is how a probe "passes vacuously": assert the mutation was
    // APPLIED as well as REACHED.
    bool      mikMutApplied = false;  // the signature byte was actually flipped
    int       probeMikType  = -1;     // 0x01 registration, 0x02 reference, -1 none found
    bool      haveProbe    = false;
    int       probeHeight  = -1;
    // PER-MIK-TYPE controls. One probe proves only the branch its own type
    // takes: a registration block verifies a signature, a reference block can
    // fail open. A single control that happened to sample a registration block
    // would therefore certify a run in which every reference block silently
    // fail-opened — the v1 defect returning in a subtler form.
    long long regBlocks    = 0;   // blocks whose MIK blob is registration-type
    long long refBlocks    = 0;   // ... reference-type
    long long noMikBlocks  = 0;   // ... no MIK blob located
    // PER-BLOCK enforcement census. Sampling proved liveness varies BLOCK BY
    // BLOCK, not by height: h83,000 fails open while h83,500 verifies, same
    // binary, same identity DB. So the only honest answer to "would the MIK
    // signature actually be enforced" is measured for every block: corrupt its
    // signature and re-check. If the corrupted block is still ACCEPTED, that
    // block's signature was never examined and enforcement would be a no-op
    // for it.
    long long mikEnforced  = 0;   // corrupting the signature flipped the verdict
    long long mikFailOpen  = 0;   // corrupted signature STILL accepted
    // WHICH identities fail open, and how many blocks each accounts for. The
    // shape of this distribution decides whether the fail-open is a small
    // population problem with a targeted fix or a systemic one.
    std::map<std::string, long long> failOpenByIdentity;
    std::map<std::string, long long> verifiedByIdentity;
    bool      regControl   = false;
    bool      refControl   = false;
    bool      regProbe     = false;
    bool      refProbe     = false;
    int       regProbeH    = -1;
    int       refProbeH    = -1;
    // ...and the LAST passing block of each type. A control on one sample
    // certifies that sample's height, not the range: measured 2026-09-05, the
    // reference-MIK arm verifies signatures at low heights and FAILS OPEN at
    // h83,000 on the same data with the same identity DB. Sampling only the
    // first passing block would print "reference arm PROVEN LIVE" for a range
    // in which most reference blocks were never actually checked.
    bool      regControlHi = false;
    bool      refControlHi = false;
    int       regProbeHiH  = -1;
    int       refProbeHiH  = -1;
    long long scanned      = 0;
    long long vdfBlocks    = 0;
    long long unreadable   = 0;
    int       tipHeight    = -1;
    int       walkedLow    = -1;
    std::vector<Failure> failures;
};

// Flip one byte INSIDE the Dilithium signature of the coinbase MIK blob,
// leaving every length and structure field intact.
//
// Deliberate and load-bearing. Corrupting arbitrary coinbase bytes would make
// the checker reject at PARSE time, and a control that fires on a parse failure
// proves only that the parser ran. The entire purpose of this control is to
// detect the fail-open branch that returns true BEFORE any signature is
// examined, so the mutation must reach the signature and nothing else.
//
//   registration: [0xDF][0x01][pubkey 1952][signature 3309]
//   reference:    [0xDF][0x02][identity  20][signature 3309]
// Read-only: the 20-byte identity of a REFERENCE MIK blob, as hex. Registration
// blobs carry a pubkey rather than a stored identity, and they verify inline,
// so the fail-open population is reference-type by construction.
std::string ReferenceIdentityHex(const CBlock& block)
{
    static const char* H = "0123456789abcdef";
    for (size_t i = 0; i + 1 < block.vtx.size(); ++i) {
        if (block.vtx[i] != DFMP::MIK_MARKER) continue;
        if (block.vtx[i + 1] != DFMP::MIK_TYPE_REFERENCE) continue;
        if (i + 2 + 20 > block.vtx.size()) return std::string();
        std::string out;
        out.reserve(40);
        for (size_t k = i + 2; k < i + 22; ++k) {
            out.push_back(H[(block.vtx[k] >> 4) & 0xF]);
            out.push_back(H[block.vtx[k] & 0xF]);
        }
        return out;
    }
    return std::string();
}

// Read-only: which MIK blob, if any, does this coinbase carry?
int DetectMIKType(const CBlock& block)
{
    for (size_t i = 0; i + 1 < block.vtx.size(); ++i) {
        if (block.vtx[i] != DFMP::MIK_MARKER) continue;
        const uint8_t t = block.vtx[i + 1];
        if (t == DFMP::MIK_TYPE_REGISTRATION || t == DFMP::MIK_TYPE_REFERENCE)
            return static_cast<int>(t);
    }
    return -1;
}

bool ForgeMIKSignatureBytes(CBlock& block, int* outType)
{
    for (size_t i = 0; i + 1 < block.vtx.size(); ++i) {
        if (block.vtx[i] != DFMP::MIK_MARKER) continue;
        const uint8_t type = block.vtx[i + 1];
        size_t body;
        if      (type == DFMP::MIK_TYPE_REGISTRATION) body = DFMP::MIK_PUBKEY_SIZE;
        else if (type == DFMP::MIK_TYPE_REFERENCE)    body = 20;
        else continue;

        const size_t sigStart = i + 2 + body;
        if (sigStart + DFMP::MIK_SIGNATURE_SIZE > block.vtx.size()) continue;
        block.vtx[sigStart + 100] ^= 0xFF;
        if (outType) *outType = static_cast<int>(type);
        return true;
    }
    return false;
}

// The one scan path. --selftest drives THIS function, not a copy, so a passing
// self-test is evidence about real runs.
ScanResult ScanChain(const std::string& blocksDir, int fromHeight, int toHeight,
                     bool verbose, const Ctx& ctx)
{
    ScanResult res;

    CBlockchainDB db;
    if (!db.Open(blocksDir, /*create_if_missing=*/false)) {
        std::cerr << "ERROR: could not open the block database at " << blocksDir << "\n"
                  << "       (never created here — point this at an existing blocks/ dir,\n"
                  << "        and stop any node using it: leveldb holds an exclusive lock)\n";
        return res;
    }
    res.opened = true;

    uint256 tipHash;
    if (!db.ReadBestBlock(tipHash)) {
        std::cerr << "ERROR: no best-block record; this database has no chain to replay\n";
        return res;
    }

    // Walk the CANONICAL chain back from the tip. The database also holds
    // orphans and stale branch blocks whose heights are not chain positions.
    std::vector<std::pair<int, uint256>> chain;
    bool brokeEarly = false;
    {
        uint256 cursor = tipHash;
        while (!cursor.IsNull()) {
            CBlockIndex idx;
            if (!db.ReadBlockIndex(cursor, idx)) { brokeEarly = true; break; }
            chain.emplace_back(idx.nHeight, cursor);
            if (idx.nHeight == 0) break;
            cursor = idx.header.hashPrevBlock;
        }
    }
    if (chain.empty()) { std::cerr << "ERROR: could not read a single block index\n"; return res; }
    std::reverse(chain.begin(), chain.end());

    res.tipHeight = chain.back().first;
    res.walkedLow = chain.front().first;

    // ASSERT completeness rather than printing two numbers and hoping a human
    // compares them. A silent mid-chain break loses the OLDEST blocks, so a
    // truncated walk can otherwise still look clean.
    res.walkComplete = (!brokeEarly && res.walkedLow == 0 &&
                        static_cast<long long>(chain.size()) ==
                        static_cast<long long>(res.tipHeight) + 1);

    // Bind the network to the data.
    res.genesisMatch = ctx.checkGenesis ? (chain.front().second == Genesis::GetGenesisHash())
                                        : true;

    if (toHeight < 0 || toHeight > res.tipHeight) toHeight = res.tipHeight;

    std::cout << "chain walked       heights " << res.walkedLow << ".." << res.tipHeight
              << " (" << chain.size() << " blocks)"
              << (res.walkComplete ? "  COMPLETE" : "  INCOMPLETE") << "\n";
    if (ctx.checkGenesis)
        std::cout << "genesis matches    "
                  << (res.genesisMatch ? "YES" : "NO — wrong --network or wrong data") << "\n";
    std::cout << "vdfIterations      " << Dilithion::g_chainParams->vdfIterations
              << "   (from --network " << ctx.network << ")\n"
              << "identity DB        " << (ctx.identityDbOpen
                    ? "OPEN — MIK signatures really verified"
                    : "ABSENT — MIK checker FAILS OPEN on reference blocks") << "\n";

    if (fromHeight > toHeight) {
        std::cout << "\nEMPTY RANGE: --from " << fromHeight << " is above the last height "
                  << toHeight << ". Nothing was checked.\n";
        return res;
    }
    std::cout << "range checked      " << fromHeight << ".." << toHeight
              << "   (gate FORCED OPEN: 'would this pass', not 'does it today')\n\n";

    uint256 probeHash, regProbeHash, refProbeHash, regProbeHiHash, refProbeHiHash;

    for (const auto& entry : chain) {
        const int h = entry.first;
        if (h < fromHeight || h > toHeight) continue;
        if (h == 0) continue;   // genesis exempt by construction (see header)

        CBlock block;
        if (!db.ReadBlock(entry.second, block)) {
            ++res.unreadable;
            // NOT a consensus failure — a local storage fault. Deliberately
            // kept out of `failures` so it can never drive the fork-height
            // number: attributing a disk fault to consensus is the wrong
            // answer on the one sentence this tool exists to produce.
            if (verbose) std::cout << "  UNREADABLE h=" << h << "\n";
            continue;
        }
        ++res.scanned;
        if (!block.IsVDFBlock()) continue;
        ++res.vdfBlocks;

        std::string e1;
        const bool okProof = CheckVDFProofConnect(block, h, block.hashPrevBlock, e1);
        if (!okProof) {
            res.failures.push_back({h, "vdf-proof", e1});
            if (verbose) std::cout << "  FAIL h=" << h << " vdf-proof: " << e1 << "\n";
        }
        std::string e2;
        const bool okMik = CheckVDFBlockMIKSignature(block, h, e2);
        if (!okMik) {
            res.failures.push_back({h, "mik-signature", e2});
            if (verbose) std::cout << "  FAIL h=" << h << " mik-signature: " << e2 << "\n";
        }

        // Per-block enforcement probe, on blocks that passed the MIK check.
        if (okMik) {
            CBlock probe = block;
            int pt = -1;
            if (ForgeMIKSignatureBytes(probe, &pt)) {
                std::string ep;
                const bool failOpen = CheckVDFBlockMIKSignature(probe, h, ep);
                if (failOpen) ++res.mikFailOpen; else ++res.mikEnforced;
                const std::string id = ReferenceIdentityHex(block);
                if (!id.empty()) {
                    if (failOpen) ++res.failOpenByIdentity[id];
                    else          ++res.verifiedByIdentity[id];
                }
            }
        }

        const int mt = DetectMIKType(block);
        if      (mt == DFMP::MIK_TYPE_REGISTRATION) ++res.regBlocks;
        else if (mt == DFMP::MIK_TYPE_REFERENCE)    ++res.refBlocks;
        else                                        ++res.noMikBlocks;

        // THE PROBE MUST BE A BLOCK THAT PASSED BOTH CHECKS — and we keep one
        // per MIK type, because the two types take different branches.
        if (okProof && okMik) {
            if (!res.haveProbe) {
                res.haveProbe = true; probeHash = entry.second; res.probeHeight = h;
            }
            if (mt == DFMP::MIK_TYPE_REGISTRATION) {
                if (!res.regProbe) { res.regProbe = true; regProbeHash = entry.second; res.regProbeH = h; }
                regProbeHiHash = entry.second; res.regProbeHiH = h;   // keep overwriting: ends up last
            }
            if (mt == DFMP::MIK_TYPE_REFERENCE) {
                if (!res.refProbe) { res.refProbe = true; refProbeHash = entry.second; res.refProbeH = h; }
                refProbeHiHash = entry.second; res.refProbeHiH = h;
            }
        }

        if (res.scanned % 10000 == 0) std::cout << "  ... " << res.scanned << " blocks\n";
    }

    // TWO INDEPENDENT MUTATION CONTROLS, one per checker, both on a block known
    // to pass clean. Each proves its own checker was live on this data.
    if (res.haveProbe) {
        CBlock clean;
        if (db.ReadBlock(probeHash, clean)) {
            std::string e;
            const bool cleanProof = CheckVDFProofConnect(clean, res.probeHeight, clean.hashPrevBlock, e);
            std::string e2;
            const bool cleanMik   = CheckVDFBlockMIKSignature(clean, res.probeHeight, e2);

            CBlock mp = clean;
            mp.vdfOutput.data[0] ^= 0x01;
            std::string e3;
            res.proofControl = cleanProof &&
                               !CheckVDFProofConnect(mp, res.probeHeight, mp.hashPrevBlock, e3);

            CBlock mm = clean;
            if (cleanMik && ForgeMIKSignatureBytes(mm, &res.probeMikType)) {
                res.mikMutApplied = true;
                std::string e4;
                res.mikControl = !CheckVDFBlockMIKSignature(mm, res.probeHeight, e4);
            }
        }
        // One control per MIK type actually present in the range.
        auto runTypeControl = [&](const uint256& hash, int height, bool& out) {
            CBlock c;
            if (!db.ReadBlock(hash, c)) return;
            std::string ea;
            if (!CheckVDFBlockMIKSignature(c, height, ea)) return;   // must pass clean
            int t = -1;
            CBlock m = c;
            if (!ForgeMIKSignatureBytes(m, &t)) return;
            std::string eb;
            out = !CheckVDFBlockMIKSignature(m, height, eb);
        };
        if (res.regProbe) runTypeControl(regProbeHash, res.regProbeH, res.regControl);
        if (res.refProbe) runTypeControl(refProbeHash, res.refProbeH, res.refControl);
        if (res.regProbeHiH >= 0) runTypeControl(regProbeHiHash, res.regProbeHiH, res.regControlHi);
        if (res.refProbeHiH >= 0) runTypeControl(refProbeHiHash, res.refProbeHiH, res.refControlHi);
        {
        }
    }
    return res;
}

// ---------------------------------------------------------------------------
// SELF-TEST
// ---------------------------------------------------------------------------

CBlock BuildSignedVDFBlock(const uint256& prevHash, int height,
                           DFMP::CMiningIdentityKey& mik, uint64_t iterations)
{
    CBlock block;
    block.nVersion      = CBlockHeader::VDF_VERSION;
    block.hashPrevBlock = prevHash;
    block.nBits         = 0x1d00ffff;
    block.nTime         = 1700000000u + static_cast<uint32_t>(height);
    block.nNonce        = 0;

    std::array<uint8_t, 20> minerAddr{};
    std::memcpy(minerAddr.data(), mik.identity.data, 20);

    auto challenge = ComputeVDFChallenge(prevHash, height, minerAddr);
    vdf::VDFConfig cfg;
    cfg.target_iterations = iterations;
    vdf::VDFResult result = vdf::compute(challenge, iterations, cfg);

    std::memcpy(block.vdfOutput.data, result.output.data(), 32);
    block.vdfProofHash = CoinbaseVDF::ComputeProofHash(result.proof);

    std::vector<uint8_t> mikSig;
    if (!mik.Sign(prevHash, height, block.nTime, mikSig)) { block.vtx.clear(); return block; }
    std::vector<uint8_t> mikScriptData;
    DFMP::BuildMIKScriptSigRegistration(mik.pubkey, mikSig, mikScriptData);

    std::vector<uint8_t> vtx;
    vtx.push_back(1);
    int32_t txVersion = 1;
    vtx.insert(vtx.end(), reinterpret_cast<uint8_t*>(&txVersion), reinterpret_cast<uint8_t*>(&txVersion) + 4);
    vtx.push_back(1);
    for (int i = 0; i < 32; ++i) vtx.push_back(0);
    uint32_t coinbaseIndex = 0xFFFFFFFF;
    vtx.insert(vtx.end(), reinterpret_cast<uint8_t*>(&coinbaseIndex), reinterpret_cast<uint8_t*>(&coinbaseIndex) + 4);

    std::vector<uint8_t> scriptSig;
    scriptSig.push_back(0x03);
    uint32_t h = static_cast<uint32_t>(height);
    scriptSig.push_back(static_cast<uint8_t>(h & 0xFF));
    scriptSig.push_back(static_cast<uint8_t>((h >> 8) & 0xFF));
    scriptSig.push_back(static_cast<uint8_t>((h >> 16) & 0xFF));
    scriptSig.insert(scriptSig.end(), mikScriptData.begin(), mikScriptData.end());
    CTxIn tempIn;
    tempIn.scriptSig = scriptSig;
    CoinbaseVDF::EmbedProof(tempIn, result.proof);
    scriptSig = tempIn.scriptSig;

    if (scriptSig.size() < 253) {
        vtx.push_back(static_cast<uint8_t>(scriptSig.size()));
    } else {
        vtx.push_back(253);
        uint16_t len16 = static_cast<uint16_t>(scriptSig.size());
        vtx.push_back(static_cast<uint8_t>(len16 & 0xFF));
        vtx.push_back(static_cast<uint8_t>((len16 >> 8) & 0xFF));
    }
    vtx.insert(vtx.end(), scriptSig.begin(), scriptSig.end());

    uint32_t seq = 0xFFFFFFFF;
    vtx.insert(vtx.end(), reinterpret_cast<uint8_t*>(&seq), reinterpret_cast<uint8_t*>(&seq) + 4);
    vtx.push_back(1);
    uint64_t value = 50ULL * 100000000ULL;
    vtx.insert(vtx.end(), reinterpret_cast<uint8_t*>(&value), reinterpret_cast<uint8_t*>(&value) + 8);
    std::vector<uint8_t> spk = {0x76, 0xa9, 0x14};
    spk.insert(spk.end(), minerAddr.begin(), minerAddr.end());
    spk.push_back(0x88); spk.push_back(0xac);
    vtx.push_back(static_cast<uint8_t>(spk.size()));
    vtx.insert(vtx.end(), spk.begin(), spk.end());
    uint32_t locktime = 0;
    vtx.insert(vtx.end(), reinterpret_cast<uint8_t*>(&locktime), reinterpret_cast<uint8_t*>(&locktime) + 4);

    block.vtx = vtx;
    SHA3_256(vtx.data() + 1, vtx.size() - 1, block.hashMerkleRoot.data);
    return block;
}

int RunSelfTest()
{
    const uint64_t iters     = 1000;
    const int      kChainLen = 8;
    const int      kForgedAt = 5;

    std::cout << "vdf-history-check SELF-TEST\n===========================\n"
              << "Building a " << kChainLen << "-block VDF chain with real proofs and real MIK\n"
              << "signatures, planting ONE forged proof at height " << kForgedAt << ", then scanning it\n"
              << "with the SAME ScanChain() a real run uses.\n\n";

    // The fixture must be built at the iteration count the checker verifies
    // against. A REAL run must NOT do this: there the shipped count is the
    // authority, being what the chain was mined against. The first version of
    // this self-test omitted it and reported 6 failures instead of 1 — the
    // self-test catching its own fixture rather than the code.
    Dilithion::g_chainParams->vdfIterations = iters;

    DFMP::CMiningIdentityKey mik;
    if (!mik.Generate()) { std::cerr << "SELF-TEST ERROR: MIK generate failed\n"; return 2; }

    std::ostringstream oss;
    oss << "dilithion-vdf-history-selftest-"
        << static_cast<unsigned long long>(std::chrono::steady_clock::now().time_since_epoch().count());
    std::filesystem::path dir = std::filesystem::temp_directory_path() / oss.str();
    std::error_code ec;
    std::filesystem::create_directories(dir, ec);

    bool built = true;
    {
        CBlockchainDB db;
        if (!db.Open(dir.string(), true)) {
            std::cerr << "SELF-TEST ERROR: could not create a temp database\n";
            std::filesystem::remove_all(dir, ec); return 2;
        }
        uint256 prev, tip;
        for (int h = 0; h < kChainLen && built; ++h) {
            CBlock b = BuildSignedVDFBlock(prev, h, mik, iters);
            if (b.vtx.empty()) { built = false; break; }
            if (h == kForgedAt) b.vdfOutput.data[0] ^= 0x01;
            uint256 hash = b.GetHash();
            CBlockIndex idx;
            idx.header = b; idx.nHeight = h; idx.nTime = b.nTime;
            idx.nBits = b.nBits; idx.nVersion = b.nVersion; idx.phashBlock = hash;
            if (!db.WriteBlock(hash, b) || !db.WriteBlockIndex(hash, idx)) { built = false; break; }
            prev = hash; tip = hash;
        }
        if (built) db.WriteBestBlock(tip);
        db.Close();
    }
    if (!built) { std::cerr << "SELF-TEST ERROR: fixture build failed\n";
                  std::filesystem::remove_all(dir, ec); return 2; }

    Ctx ctx;
    ctx.network        = "selftest-fixture";
    ctx.identityDbOpen = false;
    ctx.checkGenesis   = false;   // synthetic fixture has its own genesis

    ScanResult r = ScanChain(dir.string(), 1, -1, /*verbose=*/false, ctx);

    std::cout << "\n--- SELF-TEST VERDICT ---\n";
    bool ok = true;
    auto require = [&](bool cond, const std::string& what) {
        std::cout << (cond ? "  PASS  " : "  FAIL  ") << what << "\n";
        if (!cond) ok = false;
    };

    require(r.opened,       "the fixture database opened and a chain was walked");
    require(r.walkComplete, "the walk was ASSERTED complete (contiguous genesis..tip)");
    require(r.vdfBlocks == kChainLen - 1,
            "every non-genesis block was recognised as a VDF block");
    require(r.proofControl, "the PROOF control fired on a block that passed CLEAN");
    require(r.mikControl,   "the MIK control fired on a block that passed CLEAN");
    require(r.failures.size() == 1, "exactly ONE failure was reported");
    require(!r.failures.empty() && r.failures[0].height == kForgedAt,
            "the failure is at the planted height " + std::to_string(kForgedAt));

    if (r.failures.size() != 1) {
        std::cout << "\n  reported failures:\n";
        for (const auto& f : r.failures)
            std::cout << "    h=" << f.height << "  " << f.what << "  " << f.detail << "\n";
    }

    std::cout << (ok
        ? "\nSELF-TEST PASSED — forged proofs are detected, BOTH checkers are proven\n"
          "live by independent controls on a clean-passing block, and the tool\n"
          "asserts its own chain walk was complete.\n"
        : "\n⛔ SELF-TEST FAILED — do NOT trust this binary's output.\n");

    std::filesystem::remove_all(dir, ec);
    return ok ? 0 : 1;
}

}  // namespace

int main(int argc, char* argv[])
{
    std::string datadir, blocksdir, identitydb;
    Ctx  ctx;
    int  fromHeight = 1, toHeight = -1;   // genesis exempt by default
    bool verbose = false, selftest = false;

    try {
        for (int i = 1; i < argc; ++i) {
            std::string a = argv[i];
            auto next = [&](const char* what) -> std::string {
                if (i + 1 >= argc) { std::cerr << "ERROR: " << what << " needs a value\n"; std::exit(2); }
                return argv[++i];
            };
            if      (a == "--datadir")    datadir     = next("--datadir");
            else if (a == "--blocksdir")  blocksdir   = next("--blocksdir");
            else if (a == "--identitydb") identitydb  = next("--identitydb");
            else if (a == "--network")    ctx.network = next("--network");
            else if (a == "--from")       fromHeight  = std::stoi(next("--from"));
            else if (a == "--to")         toHeight    = std::stoi(next("--to"));
            else if (a == "--verbose")    verbose     = true;
            else if (a == "--selftest")   selftest    = true;
            else if (a == "--help" || a == "-h") { Usage(); return 0; }
            else { std::cerr << "ERROR: unknown argument " << a << "\n\n"; Usage(); return 2; }
        }
    } catch (const std::exception& e) {
        std::cerr << "ERROR: bad numeric argument (" << e.what() << ")\n";
        return 2;
    }

    if (selftest && (!datadir.empty() || !blocksdir.empty())) {
        std::cerr << "ERROR: --selftest exercises a synthetic fixture and ignores your data.\n"
                     "       Refusing to run it alongside --datadir/--blocksdir, because exit 0\n"
                     "       would then mean 'the binary self-checked', not 'the chain is clean'.\n";
        return 2;
    }
    if (!selftest && datadir.empty() && blocksdir.empty()) { Usage(); return 2; }
    if (!InstallParams(ctx.network)) {
        if (!selftest) { std::cerr << "ERROR: unknown --network " << ctx.network << "\n"; return 2; }
        InstallParams("dilv");
    }
    if (!vdf::init()) { std::cerr << "ERROR: failed to initialise the VDF library\n"; return 2; }

    if (selftest) { const int rc = RunSelfTest(); vdf::shutdown(); return rc; }

    if (blocksdir.empty()) blocksdir = datadir + "/blocks";

    // Open the identity DB if we can. Without it CheckVDFBlockMIKSignature
    // fail-opens on every reference-MIK block, and that half of the answer is
    // worthless — so the tool reports it UNMEASURED rather than passing.
    const std::string idPath = !identitydb.empty() ? identitydb : datadir;
    if (!idPath.empty()) {
        ctx.identityDbOpen = DFMP::InitializeDFMP(idPath) && DFMP::g_identityDb != nullptr;
    }

    std::cout << "network            " << ctx.network << "\n"
              << "blocks             " << blocksdir << "\n";

    ScanResult r = ScanChain(blocksdir, fromHeight, toHeight, verbose, ctx);
    if (!r.opened) { vdf::shutdown(); return 2; }

    std::cout << "\n---------------------------------------------------------------\n"
              << "blocks read        " << r.scanned << "\n"
              << "VDF blocks checked " << r.vdfBlocks << "\n"
              << "unreadable bodies  " << r.unreadable << "   (storage faults, NOT consensus failures)\n"
              << "failure entries    " << r.failures.size()
              << "   (a block failing both checks contributes two)\n"
              << "proof control      " << (r.proofControl ? "FIRED" : "DID NOT FIRE") << "\n"
              << "MIK control        " << (r.mikControl ? "FIRED"
                    : (r.mikMutApplied ? "DID NOT FIRE (mutation WAS applied)"
                                       : "NOT APPLIED (no MIK blob located in the probe)")) << "\n"
              << "probe block        height " << r.probeHeight << ", MIK type "
              << (r.probeMikType == 0x01 ? "REGISTRATION"
                 : r.probeMikType == 0x02 ? "REFERENCE" : "none located") << "\n"
              << "MIK ENFORCEMENT    " << r.mikEnforced << " blocks really verified | "
              << r.mikFailOpen << " FAIL OPEN (signature never examined)";
    if (r.mikEnforced + r.mikFailOpen > 0)
        std::cout << "  = " << (100.0 * r.mikFailOpen / (r.mikEnforced + r.mikFailOpen))
                  << "% unenforced";
    std::cout << "\n"
              << "MIK blob census    registration " << r.regBlocks
              << " | reference " << r.refBlocks
              << " | none " << r.noMikBlocks << "\n"
              << "  registration arm low h" << r.regProbeH << " "
                    << (r.regBlocks == 0 ? "n/a" : r.regControl ? "LIVE" : "NOT LIVE")
                    << "   high h" << r.regProbeHiH << " "
                    << (r.regBlocks == 0 ? "n/a" : r.regControlHi ? "LIVE" : "NOT LIVE") << "\n"
              << "  reference arm    low h" << r.refProbeH << " "
                    << (r.refBlocks == 0 ? "n/a" : r.refControl ? "LIVE" : "NOT LIVE")
                    << "   high h" << r.refProbeHiH << " "
                    << (r.refBlocks == 0 ? "n/a" : r.refControlHi ? "LIVE" : "NOT LIVE") << "\n";

    // Every reason the run cannot be trusted, reported together rather than one
    // at a time, so an operator sees the whole picture in a single pass.
    std::vector<std::string> untrusted;
    if (!r.walkComplete)
        untrusted.push_back("the chain walk was INCOMPLETE — heights " + std::to_string(r.walkedLow)
            + ".." + std::to_string(r.tipHeight) + " is not a contiguous genesis..tip span, so blocks exist that were never scanned");
    if (!r.genesisMatch)
        untrusted.push_back("genesis does NOT match --network " + ctx.network
            + " — wrong network or wrong data; every block would fail for that reason alone");
    if (r.vdfBlocks == 0)
        untrusted.push_back("no VDF block was checked, so nothing was verified");
    if (!r.haveProbe)
        untrusted.push_back("no block passed both checks, so neither control could run");
    if (!r.proofControl)
        untrusted.push_back("the PROOF control did not fire — the proof checker was not live on this data");
    if (r.regBlocks > 0 && !r.regControl)
        untrusted.push_back("REGISTRATION-MIK blocks were present (" + std::to_string(r.regBlocks)
            + ") but no control proved that branch live — their signatures may be unverified");
    if (r.mikFailOpen > 0)
        untrusted.push_back(std::to_string(r.mikFailOpen) + " of "
            + std::to_string(r.mikEnforced + r.mikFailOpen)
            + " blocks FAIL OPEN on the MIK signature — their signatures were never examined, so "
              "activating enforcement would NOT enforce the MIK half for them. This is measured "
              "per block, not sampled.");
    if (r.regBlocks > 0 && r.regControl && !r.regControlHi)
        untrusted.push_back("the REGISTRATION-MIK arm is live at the BOTTOM of the range (h"
            + std::to_string(r.regProbeH) + ") but NOT at the top (h" + std::to_string(r.regProbeHiH)
            + ") — signature checking stops somewhere inside this range, so an absence of failures "
              "above that point is not evidence");
    if (r.refBlocks > 0 && r.refControl && !r.refControlHi)
        untrusted.push_back("the REFERENCE-MIK arm is live at the BOTTOM of the range (h"
            + std::to_string(r.refProbeH) + ") but FAILS OPEN at the top (h" + std::to_string(r.refProbeHiH)
            + ") — signatures stop being examined somewhere inside this range, so an absence of "
              "MIK failures above that point proves NOTHING. Bisect to find where.");
    if (r.refBlocks > 0 && !r.refControl)
        untrusted.push_back("REFERENCE-MIK blocks were present (" + std::to_string(r.refBlocks)
            + ") and the control on that branch DID NOT FIRE — CheckVDFBlockMIKSignature FAILS OPEN "
              "for them (identity not resolvable from the identity DB), so their signatures were "
              "never examined. Any 'pass' for those blocks is worthless.");
    if (!r.mikControl && r.mikMutApplied)
        untrusted.push_back("the MIK signature WAS corrupted and the checker STILL ACCEPTED the block — "
            "so CheckVDFBlockMIKSignature is not verifying signatures on this data. With the identity DB "
            "open this means the probe's MIK identity is not resolvable from it, so the checker takes its "
            "fail-open branch. The MIK half of any 'pass' here is worth nothing.");
    if (!r.mikControl && !r.mikMutApplied)
        untrusted.push_back("no MIK blob could be located in the probe block, so the MIK control was never "
            "applied — this is a TOOL limitation, not evidence about the chain. Do not read it either way.");

    if (!r.failOpenByIdentity.empty() || !r.verifiedByIdentity.empty()) {
        std::vector<std::pair<long long, std::string>> top;
        for (const auto& kv : r.failOpenByIdentity) top.push_back({kv.second, kv.first});
        std::sort(top.rbegin(), top.rend());
        std::cout << "\nFAIL-OPEN IDENTITIES  " << r.failOpenByIdentity.size()
                  << " distinct, out of " << r.verifiedByIdentity.size()
                  << " that verified at least once\n";
        for (size_t i = 0; i < top.size() && i < 12; ++i) {
            auto it = r.verifiedByIdentity.find(top[i].second);
            const long long ver = (it == r.verifiedByIdentity.end() ? 0 : it->second);
            std::cout << "   " << top[i].second << "  " << top[i].first
                      << " fail-open" << (ver ? "  (+" + std::to_string(ver) + " verified — MIXED)"
                                              : "  (never verified)") << "\n";
        }
        if (top.size() > 12) std::cout << "   ... and " << (top.size() - 12) << " more\n";
    }

    // Failure DETAIL is printed even on an untrusted run. Suppressing it meant a
    // 4-hour census reported "3 failure entries" and no heights, which made the
    // failures undiagnosable without re-running.
    if (!r.failures.empty()) {
        std::cout << "\nconsensus failures (" << r.failures.size() << "):\n";
        for (const auto& f : r.failures)
            std::cout << "   h=" << f.height << "  " << f.what << "  " << f.detail << "\n";
    }

    if (!untrusted.empty()) {
        std::cout << "\n⛔ RESULT: UNTRUSTWORTHY. This run cannot support a fork-height decision:\n";
        for (const auto& u : untrusted) std::cout << "   * " << u << "\n";
        if (!ctx.identityDbOpen)
            std::cout << "\n   The MIK half is UNMEASURED. Re-run with --datadir pointing at a node\n"
                         "   datadir that contains dfmp_identity/ to measure it.\n";
        if (!r.failures.empty())
            std::cout << "\n   " << r.failures.size() << " failure entries were also seen. Do not act on\n"
                         "   them until the above is resolved.\n";
        vdf::shutdown();
        return 2;
    }

    if (r.failures.empty()) {
        std::cout << "\nRESULT: all " << r.vdfBlocks << " VDF blocks in " << fromHeight << ".."
                  << (toHeight < 0 ? r.tipHeight : toHeight) << " PASS.\n"
                  << "Both checkers proven live by independent controls, walk proven complete,\n"
                  << "network bound to the data by genesis hash.\n"
                  << "A fork height inside this range would not have halted the chain.\n"
                  << "This says NOTHING about heights above " << r.tipHeight << ".\n";
        vdf::shutdown();
        return 0;
    }

    int worst = 0, lowest = INT32_MAX;
    std::map<std::string, int> byKind;
    for (const auto& f : r.failures) {
        worst  = std::max(worst, f.height);
        lowest = std::min(lowest, f.height);
        byKind[f.what]++;
    }
    const int scanTop      = (toHeight < 0 ? r.tipHeight : toHeight);
    const int recentWindow = 1000;
    const bool recent      = (worst > scanTop - recentWindow);

    std::cout << "\nfailures by kind:\n";
    for (const auto& kv : byKind) std::cout << "  " << kv.first << ": " << kv.second << "\n";
    std::cout << "failing heights: ";
    for (size_t i = 0; i < r.failures.size() && (verbose || i < 10); ++i)
        std::cout << r.failures[i].height << " ";
    if (!verbose && r.failures.size() > 10) std::cout << "... (--verbose for all)";
    std::cout << "\nspan " << lowest << ".." << worst << ", in a scan ending at " << scanTop << "\n";

    if (recent) {
        // The case that actually decides the fork, and where handing over a
        // floor is dangerous: blocks near the tip failing means miners running
        // NOW emit blocks that would be rejected. There is no safe height.
        std::cout << "\n⛔ RESULT: FAILURES REACH THE TOP OF THE SCANNED RANGE (highest " << worst
                  << ", within " << recentWindow << " of " << scanTop << ").\n"
                  << "DO NOT PIN ANY HEIGHT. This is the signature of blocks being produced right now\n"
                  << "that would be REJECTED under enforcement — activating at any height would halt\n"
                  << "the chain almost immediately. Find the cause first. No floor is offered here\n"
                  << "because there is not a safe one.\n";
    } else {
        std::cout << "\n⛔ RESULT: " << r.failures.size() << " failure entries, all at or below height "
                  << worst << ",\nwhich is more than " << recentWindow << " blocks below the top of the scanned range.\n"
                  << "That is consistent with an OLD regime that later changed, not with a live fault.\n"
                  << "A fork height must be above " << worst << ". That is a FLOOR from THIS data only:\n"
                  << "it says nothing about heights above " << r.tipHeight << ", and margin for miner\n"
                  << "upgrade is a separate question this tool does not answer.\n";
    }

    vdf::shutdown();
    return 1;
}
