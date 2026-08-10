// Copyright (c) 2026 The Dilithion Core developers
// Distributed under the MIT software license

#include <dfmp/mik_registration_file.h>

#include <crypto/sha3.h>
#include <dfmp/mik.h>
#include <util/atomic_file.h>

#include <cstdio>
#include <string>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <system_error>

namespace DFMP {

const char* const MIK_REGISTRATION_FILENAME = "mik_registration.dat";

namespace {

constexpr char kMagic[4] = {'M', 'R', 'P', 'W'};
constexpr uint32_t kVersion = 1;
constexpr size_t kPubkeyBytes = MIK_PUBKEY_SIZE;   // 1952
constexpr size_t kDnaBytes = 32;
constexpr size_t kChecksumBytes = 32;

// Fixed layout size (excluding checksum)
constexpr size_t kPayloadSize =
    sizeof(kMagic) + sizeof(kVersion) + kPubkeyBytes + kDnaBytes + sizeof(uint64_t) + sizeof(int64_t);
constexpr size_t kTotalSize = kPayloadSize + kChecksumBytes;

void AppendLE32(std::vector<uint8_t>& buf, uint32_t v) {
    for (int i = 0; i < 4; ++i) buf.push_back(static_cast<uint8_t>((v >> (8 * i)) & 0xFF));
}
void AppendLE64(std::vector<uint8_t>& buf, uint64_t v) {
    for (int i = 0; i < 8; ++i) buf.push_back(static_cast<uint8_t>((v >> (8 * i)) & 0xFF));
}
uint32_t ReadLE32(const uint8_t* p) {
    uint32_t v = 0;
    for (int i = 0; i < 4; ++i) v |= static_cast<uint32_t>(p[i]) << (8 * i);
    return v;
}
uint64_t ReadLE64(const uint8_t* p) {
    uint64_t v = 0;
    for (int i = 0; i < 8; ++i) v |= static_cast<uint64_t>(p[i]) << (8 * i);
    return v;
}

std::filesystem::path FilePath(const std::string& datadir) {
    return std::filesystem::path(datadir) / MIK_REGISTRATION_FILENAME;
}

} // namespace

bool SaveMIKRegistration(const std::string& datadir,
                         const std::vector<uint8_t>& pubkey,
                         const std::array<uint8_t, 32>& dnaHash,
                         uint64_t nonce,
                         int64_t timestamp) {
    if (pubkey.size() != kPubkeyBytes) return false;

    std::vector<uint8_t> payload;
    payload.reserve(kPayloadSize);
    payload.insert(payload.end(), kMagic, kMagic + sizeof(kMagic));
    AppendLE32(payload, kVersion);
    payload.insert(payload.end(), pubkey.begin(), pubkey.end());
    payload.insert(payload.end(), dnaHash.begin(), dnaHash.end());
    AppendLE64(payload, nonce);
    AppendLE64(payload, static_cast<uint64_t>(timestamp));

    uint8_t checksum[32];
    SHA3_256(payload.data(), payload.size(), checksum);

    std::filesystem::path finalPath = FilePath(datadir);
    std::filesystem::path tmpPath = finalPath;
    tmpPath += ".tmp";

    {
        std::ofstream out(tmpPath, std::ios::binary | std::ios::trunc);
        if (!out.is_open()) return false;
        out.write(reinterpret_cast<const char*>(payload.data()), payload.size());
        out.write(reinterpret_cast<const char*>(checksum), kChecksumBytes);
        if (!out.good()) return false;
        out.flush();
    }

    // Publish atomically. This file holds a MINED registration proof-of-work —
    // it is not reconstructible from chain, so losing it costs the operator real
    // work. The previous code here did fs::rename and, on failure, fell back to
    // remove-then-rename; on Windows fs::rename ALWAYS fails when the
    // destination exists, so the fallback was the normal path and every update
    // ran through a window in which mik_registration.dat did not exist at all.
    // durable=true: MOVEFILE_WRITE_THROUGH / parent-dir fsync.
    // See src/util/atomic_file.h.
    std::string moveErr;
    if (!util::AtomicReplaceFile(tmpPath, finalPath, &moveErr, /*durable=*/true)) {
        std::error_code rm_ec;
        std::filesystem::remove(tmpPath, rm_ec);  // previous file left intact
        return false;
    }
    return true;
}

static void RenameStale(const std::filesystem::path& finalPath, const char* suffix) {
    std::filesystem::path dest = finalPath;
    dest += suffix;
    std::error_code ec;
    std::filesystem::remove(dest, ec);
    std::filesystem::rename(finalPath, dest, ec);
    // Ignore errors — best-effort forensic trail
}

MIKRegFileLoadResult LoadMIKRegistration(const std::string& datadir,
                                         const std::vector<uint8_t>& expectedPubkey,
                                         MIKRegistrationFile& out) {
    std::filesystem::path path = FilePath(datadir);
    std::error_code ec;
    if (!std::filesystem::exists(path, ec)) return MIKRegFileLoadResult::Missing;

    std::ifstream in(path, std::ios::binary | std::ios::ate);
    if (!in.is_open()) return MIKRegFileLoadResult::Corrupt;

    std::streamsize size = in.tellg();
    if (size != static_cast<std::streamsize>(kTotalSize)) {
        in.close();
        RenameStale(path, ".corrupt");
        return MIKRegFileLoadResult::Corrupt;
    }
    in.seekg(0);

    std::vector<uint8_t> buf(kTotalSize);
    in.read(reinterpret_cast<char*>(buf.data()), kTotalSize);
    if (!in.good()) {
        in.close();
        RenameStale(path, ".corrupt");
        return MIKRegFileLoadResult::Corrupt;
    }
    in.close();

    // Verify checksum
    uint8_t expected[32];
    SHA3_256(buf.data(), kPayloadSize, expected);
    if (std::memcmp(expected, buf.data() + kPayloadSize, kChecksumBytes) != 0) {
        RenameStale(path, ".corrupt");
        return MIKRegFileLoadResult::Corrupt;
    }

    // Parse fields
    size_t off = 0;
    if (std::memcmp(buf.data() + off, kMagic, sizeof(kMagic)) != 0) {
        RenameStale(path, ".corrupt");
        return MIKRegFileLoadResult::Corrupt;
    }
    off += sizeof(kMagic);

    uint32_t version = ReadLE32(buf.data() + off);
    off += 4;
    if (version != kVersion) {
        RenameStale(path, ".corrupt");
        return MIKRegFileLoadResult::Corrupt;
    }

    out.pubkey.assign(buf.data() + off, buf.data() + off + kPubkeyBytes);
    off += kPubkeyBytes;

    std::memcpy(out.dnaHash.data(), buf.data() + off, kDnaBytes);
    off += kDnaBytes;

    out.nonce = ReadLE64(buf.data() + off);
    off += 8;

    out.timestamp = static_cast<int64_t>(ReadLE64(buf.data() + off));
    off += 8;

    // Pubkey binding check
    if (!expectedPubkey.empty()) {
        if (expectedPubkey.size() != kPubkeyBytes ||
            std::memcmp(expectedPubkey.data(), out.pubkey.data(), kPubkeyBytes) != 0) {
            RenameStale(path, ".stale");
            return MIKRegFileLoadResult::PubkeyMismatch;
        }
    }

    return MIKRegFileLoadResult::OK;
}

} // namespace DFMP
