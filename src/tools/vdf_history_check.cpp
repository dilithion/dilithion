// Copyright (c) 2026 The Dilithion Core developers
// Distributed under the MIT software license
//
// vdf-history-check — replay the LP-10 VDF consensus checks over stored blocks.
//
// WHY THIS EXISTS. `vdfProofEnforcementHeight` activates a consensus check that
// every DilV block must then satisfy: a verifying Wesolowski proof AND a valid
// coinbase MIK signature. Every DilV block is a VDF block (vdfActivationHeight
// = 0), so if blocks being mined today would NOT pass, pinning any height HALTS
// the chain at that height. Nobody can answer that from RPC: `getblock` returns
// no vdfOutput, no vdfProofHash, no raw hex and no coinbase scriptSig at any
// verbosity, and the proof lives in the scriptSig. It has to be replayed
// against stored blocks, on a binary that contains the checkers.
//
// The precedent cited across the fleet for this is `tool/nbits-history-check`,
// whose lesson was that an un-measured connect-time belt would have stuck every
// fresh DIL sync at height 7,034. NOTE, measured 2026-09-05: that tool exists on
// NO remote branch of this repository. If you came looking for it as a
// template, it is not here.
//
// WHAT IT REPORTS. For every block in range it runs the two production checkers
// with the activation gate FORCED OPEN, so the answer is "would this block pass
// if enforcement were live", not "does it pass today" — today nothing is
// enforced, the sentinel being 999999999 on all four networks. It then prints
// the highest failing height, because a fork height must not be set at or below
// it.
//
// ⚠️ IT REFUSES TO REPORT A CLEAN RUN IT CANNOT PROVE. A replay that silently
// stopped checking looks exactly like a replay that found nothing wrong. So
// every run ends with a MUTATION CONTROL: a real block from the very data just
// scanned is corrupted in memory and re-checked, and the run is declared
// UNTRUSTWORTHY if the checker still accepts it. "All pass" is never printed
// without positive evidence that the checker was live against this data.
//
// ⚠️ AND THE BINARY CAN PROVE ITSELF: `--selftest` builds a real VDF chain with
// a single planted forgery and requires the scan to find exactly it. Run that
// before trusting any real run.

#include <consensus/vdf_validation.h>
#include <core/chainparams.h>
#include <crypto/sha3.h>
#include <dfmp/dfmp.h>
#include <dfmp/mik.h>
#include <node/blockchain_storage.h>
#include <node/block_index.h>
#include <primitives/block.h>
#include <vdf/coinbase_vdf.h>
#include <vdf/vdf.h>

#include <algorithm>
#include <array>
#include <chrono>
#include <cstring>
#include <filesystem>
#include <iostream>
#include <map>
#include <sstream>
#include <string>
#include <vector>

namespace {

void Usage()
{
    std::cout <<
        "vdf-history-check — replay LP-10 VDF checks over stored blocks\n\n"
        "  --datadir <path>     block database directory (required unless --selftest)\n"
        "  --network <n>        dilv | mainnet | testnet | regtest   (default dilv)\n"
        "  --from <height>      first height to check (default 0)\n"
        "  --to <height>        last height to check (default: chain tip)\n"
        "  --verbose            print every failing height, not just a summary\n"
        "  --selftest           prove this binary detects a forged proof, then exit\n\n"
        "Exit: 0 all checked blocks pass; 1 one or more fail; 2 the run could\n"
        "      not be trusted (no data, or the mutation control did not fire).\n";
}

bool InstallParams(const std::string& network)
{
    using Dilithion::ChainParams;
    ChainParams p;
    if      (network == "dilv")    p = ChainParams::DilV();
    else if (network == "mainnet") p = ChainParams::Mainnet();
    else if (network == "testnet") p = ChainParams::Testnet();
    else if (network == "regtest") p = ChainParams::Regtest();
    else return false;

    if (Dilithion::g_chainParams == nullptr) {
        Dilithion::g_chainParams = new ChainParams(p);
    } else {
        *Dilithion::g_chainParams = p;
    }

    // FORCE THE ACTIVATION GATE OPEN. Both checkers begin
    // `if (height < vdfProofEnforcementHeight) return true;` and every network
    // ships the 999999999 sentinel, so with real params this tool would report
    // a flawless chain while verifying nothing at all — exactly the vacuous
    // green it exists to prevent. Setting 0 makes every block truly checked.
    Dilithion::g_chainParams->vdfProofEnforcementHeight = 0;
    return true;
}

struct Failure {
    int         height;
    std::string what;
    std::string detail;
};

struct ScanResult {
    bool                 opened      = false;
    bool                 trustworthy = false;  // the mutation control fired
    long long            scanned     = 0;
    long long            vdfBlocks   = 0;
    long long            unreadable  = 0;
    int                  tipHeight   = -1;
    std::vector<Failure> failures;
};

// The one scan path. `--selftest` drives THIS function, not a copy of it, so a
// passing self-test is evidence about real runs rather than about a parallel
// implementation that happens to agree.
ScanResult ScanChain(const std::string& datadir, int fromHeight, int toHeight, bool verbose)
{
    ScanResult res;

    CBlockchainDB db;
    if (!db.Open(datadir, /*create_if_missing=*/false)) {
        std::cerr << "ERROR: could not open the block database at " << datadir << "\n"
                  << "       (this tool never creates one — point it at an existing datadir)\n";
        return res;
    }
    res.opened = true;

    uint256 tipHash;
    if (!db.ReadBestBlock(tipHash)) {
        std::cerr << "ERROR: no best-block record; this database has no chain to replay\n";
        return res;
    }

    // Walk the CANONICAL chain backwards from the tip via pprev-by-hash rather
    // than enumerating every stored hash: the database also holds orphans and
    // stale branch blocks, whose heights are not chain positions. Replaying
    // those would report failures that never mattered to consensus.
    std::vector<std::pair<int, uint256>> chain;   // tip-first
    {
        uint256 cursor = tipHash;
        while (!cursor.IsNull()) {
            CBlockIndex idx;
            if (!db.ReadBlockIndex(cursor, idx)) break;
            chain.emplace_back(idx.nHeight, cursor);
            if (idx.nHeight == 0) break;
            cursor = idx.header.hashPrevBlock;
        }
    }
    if (chain.empty()) {
        std::cerr << "ERROR: could not read a single block index\n";
        return res;
    }
    std::reverse(chain.begin(), chain.end());     // genesis-first

    res.tipHeight = chain.back().first;
    if (toHeight < 0 || toHeight > res.tipHeight) toHeight = res.tipHeight;

    std::cout << "canonical blocks   " << chain.size() << " (tip height " << res.tipHeight << ")\n"
              << "range checked      " << fromHeight << " .. " << toHeight << "\n"
              << "enforcement gate   FORCED OPEN (asking 'would this pass', not 'does it today')\n\n";

    uint256 sampleHash;
    int     sampleHeight = -1;
    bool    haveSample   = false;

    for (const auto& entry : chain) {
        const int h = entry.first;
        if (h < fromHeight || h > toHeight) continue;

        CBlock block;
        if (!db.ReadBlock(entry.second, block)) {
            ++res.unreadable;
            res.failures.push_back({h, "unreadable", "index exists but the block body could not be read"});
            continue;
        }
        ++res.scanned;
        if (!block.IsVDFBlock()) continue;
        ++res.vdfBlocks;

        if (!haveSample) { sampleHash = entry.second; sampleHeight = h; haveSample = true; }

        std::string err;
        if (!CheckVDFProofConnect(block, h, block.hashPrevBlock, err)) {
            res.failures.push_back({h, "vdf-proof", err});
            if (verbose) std::cout << "  FAIL h=" << h << " vdf-proof: " << err << "\n";
        }
        err.clear();
        if (!CheckVDFBlockMIKSignature(block, h, err)) {
            res.failures.push_back({h, "mik-signature", err});
            if (verbose) std::cout << "  FAIL h=" << h << " mik-signature: " << err << "\n";
        }

        if (res.scanned % 10000 == 0) std::cout << "  ... " << res.scanned << " blocks\n";
    }

    // MUTATION CONTROL — the run is not trustworthy without it. Corrupt a REAL
    // block from the data just scanned and require the checker to reject it.
    // This proves the checker was live against THIS database, rather than
    // merely that no failure happened to be printed.
    if (haveSample) {
        CBlock probe;
        if (db.ReadBlock(sampleHash, probe)) {
            probe.vdfOutput.data[0] ^= 0x01;
            std::string err;
            res.trustworthy = !CheckVDFProofConnect(probe, sampleHeight, probe.hashPrevBlock, err);
        }
    }
    return res;
}

// ---------------------------------------------------------------------------
// SELF-TEST
// ---------------------------------------------------------------------------

// Build a VDF block carrying a real Wesolowski proof and a real registration-MIK
// signature. Deliberately self-contained rather than shared with
// src/vdf/vdf_consensus_test.cpp: that file is a converged, thrice-reviewed
// suite and this tool must not be able to break it. If a third consumer
// appears, factor these out then.
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
    const int      kChainLen = 6;
    const int      kForgedAt = 4;    // the single planted forgery

    std::cout << "vdf-history-check SELF-TEST\n"
              << "===========================\n"
              << "Building a " << kChainLen << "-block VDF chain with real proofs and real MIK\n"
              << "signatures, planting ONE forged proof at height " << kForgedAt << ", then scanning\n"
              << "it with the SAME ScanChain() a real run uses.\n\n";

    // The fixture must be built at the SAME iteration count the checker will
    // verify against. CheckVDFProof reads g_chainParams->vdfIterations, which
    // for DilV is 500,000 — computing a 1,000-iteration proof and verifying it
    // against 500,000 fails every block, honest ones included. The first run of
    // this self-test did exactly that and reported 6 failures instead of 1,
    // which is the self-test doing its job on its own fixture.
    //
    // A REAL run must NOT do this: there the shipped vdfIterations is the
    // authority, because it is what the chain was mined against.
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
            std::filesystem::remove_all(dir, ec);
            return 2;
        }
        uint256 prev, tip;
        for (int h = 0; h < kChainLen && built; ++h) {
            CBlock b = BuildSignedVDFBlock(prev, h, mik, iters);
            if (b.vtx.empty()) { std::cerr << "SELF-TEST ERROR: build failed at h=" << h << "\n"; built = false; break; }
            if (h == kForgedAt) b.vdfOutput.data[0] ^= 0x01;

            uint256 hash = b.GetHash();
            CBlockIndex idx;
            idx.header     = b;
            idx.nHeight    = h;
            idx.nTime      = b.nTime;
            idx.nBits      = b.nBits;
            idx.nVersion   = b.nVersion;
            idx.phashBlock = hash;

            if (!db.WriteBlock(hash, b) || !db.WriteBlockIndex(hash, idx)) {
                std::cerr << "SELF-TEST ERROR: write failed at h=" << h << "\n"; built = false; break;
            }
            prev = hash;
            tip  = hash;
        }
        if (built) db.WriteBestBlock(tip);
        db.Close();
    }
    if (!built) { std::filesystem::remove_all(dir, ec); return 2; }

    ScanResult r = ScanChain(dir.string(), 0, -1, /*verbose=*/false);

    if (r.failures.size() != 1) {
        std::cout << "\nfailures reported (" << r.failures.size() << "), expected exactly 1:\n";
        for (const auto& f : r.failures)
            std::cout << "    h=" << f.height << "  " << f.what << "  " << f.detail << "\n";
    }

    std::cout << "\n--- SELF-TEST VERDICT ---\n";
    bool ok = true;
    auto require = [&](bool cond, const std::string& what) {
        std::cout << (cond ? "  PASS  " : "  FAIL  ") << what << "\n";
        if (!cond) ok = false;
    };

    require(r.opened,                  "the temp database opened and a chain was walked");
    require(r.vdfBlocks == kChainLen,  "every block was recognised as a VDF block");
    require(r.trustworthy,             "the mutation control FIRED (the checker was live)");
    require(r.failures.size() == 1,    "exactly ONE failure was reported");
    require(!r.failures.empty() && r.failures[0].height == kForgedAt,
            "the failure is at the planted height " + std::to_string(kForgedAt));
    // The decisive one: a scan reporting nothing on a chain that provably
    // contains a forgery is the vacuous green this tool exists to make
    // impossible.
    require(!r.failures.empty(),       "a planted forgery could NOT be silently missed");

    std::cout << (ok
        ? "\nSELF-TEST PASSED — this binary detects a forged proof in stored blocks,\n"
          "and refuses to call a run clean unless its checker was live.\n"
        : "\n⛔ SELF-TEST FAILED — do NOT trust this binary's output.\n");

    std::filesystem::remove_all(dir, ec);
    return ok ? 0 : 1;
}

}  // namespace

int main(int argc, char* argv[])
{
    std::string datadir, network = "dilv";
    int  fromHeight = 0, toHeight = -1;
    bool verbose = false, selftest = false;

    for (int i = 1; i < argc; ++i) {
        std::string a = argv[i];
        auto next = [&](const char* what) -> std::string {
            if (i + 1 >= argc) { std::cerr << "ERROR: " << what << " needs a value\n"; std::exit(2); }
            return argv[++i];
        };
        if      (a == "--datadir")  datadir    = next("--datadir");
        else if (a == "--network")  network    = next("--network");
        else if (a == "--from")     fromHeight = std::stoi(next("--from"));
        else if (a == "--to")       toHeight   = std::stoi(next("--to"));
        else if (a == "--verbose")  verbose    = true;
        else if (a == "--selftest") selftest   = true;
        else if (a == "--help" || a == "-h") { Usage(); return 0; }
        else { std::cerr << "ERROR: unknown argument " << a << "\n\n"; Usage(); return 2; }
    }

    if (!selftest && datadir.empty()) { Usage(); return 2; }
    if (!InstallParams(network)) { std::cerr << "ERROR: unknown --network " << network << "\n"; return 2; }
    if (!vdf::init()) { std::cerr << "ERROR: failed to initialise the VDF library\n"; return 2; }

    if (selftest) { int rc = RunSelfTest(); vdf::shutdown(); return rc; }

    std::cout << "network            " << network << "\n"
              << "datadir            " << datadir << "\n";

    ScanResult r = ScanChain(datadir, fromHeight, toHeight, verbose);
    if (!r.opened) { vdf::shutdown(); return 2; }

    std::cout << "\n---------------------------------------------------------------\n"
              << "blocks read        " << r.scanned << "\n"
              << "VDF blocks checked " << r.vdfBlocks << "\n"
              << "unreadable bodies  " << r.unreadable << "\n"
              << "failures           " << r.failures.size() << "\n";

    if (r.vdfBlocks == 0) {
        std::cout << "\nRESULT: UNTRUSTWORTHY — no VDF block was checked in this range, so\n"
                     "nothing was verified and the mutation control could not run.\n";
        vdf::shutdown();
        return 2;
    }
    if (!r.trustworthy) {
        std::cout << "\n⛔ RESULT: UNTRUSTWORTHY — the mutation control DID NOT FIRE.\n"
                     "A deliberately corrupted block from this very database was still\n"
                     "ACCEPTED, so the checker was not live and every 'pass' above is\n"
                     "meaningless. Do not pin a height on this run.\n";
        vdf::shutdown();
        return 2;
    }
    std::cout << "mutation control   FIRED (a corrupted block from this data was rejected)\n";

    if (r.failures.empty()) {
        std::cout << "\nRESULT: ALL " << r.vdfBlocks << " VDF blocks checked PASS, and the checker is\n"
                     "proven live. A fork height in this range would not have halted the chain.\n";
        vdf::shutdown();
        return 0;
    }

    int worst = 0;
    std::map<std::string, int> byKind;
    for (const auto& f : r.failures) { worst = std::max(worst, f.height); byKind[f.what]++; }

    std::cout << "\nfailures by kind:\n";
    for (const auto& kv : byKind) std::cout << "  " << kv.first << ": " << kv.second << "\n";

    std::cout << "\nfailing heights: ";
    for (size_t i = 0; i < r.failures.size() && (verbose || i < 10); ++i)
        std::cout << r.failures[i].height << " ";
    if (!verbose && r.failures.size() > 10) std::cout << "... (--verbose for all)";
    std::cout << "\n";

    std::cout << "\n⛔ RESULT: " << r.failures.size() << " failures, the highest at height " << worst << ".\n"
              << "PINNING A FORK HEIGHT AT OR BELOW " << worst << " WOULD HALT THE CHAIN THERE.\n"
              << "The first height with nothing failing above it is " << (worst + 1) << " — a floor from\n"
              << "THIS data only, not a recommendation. Re-run against a fresh tip before\n"
              << "pinning, and add margin for miner upgrade.\n";

    vdf::shutdown();
    return 1;
}
