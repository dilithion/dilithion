// Copyright (c) 2026 The Dilithion Core developers
// Distributed under the MIT software license
//
// v4.4 Block 9 follow-up: chainstate corruption injection tool.
//
// PURPOSE
// =======
// Surgically corrupt a single undo entry in a real DilV chainstate LevelDB
// so we can empirically validate that the v4.4 binary's startup integrity
// check detects production-shape corruption against production-shape data.
//
// USAGE
// =====
//   v4_4_inject_undo_corruption <datadir-path> --mode=delete --target=tip
//   v4_4_inject_undo_corruption <datadir-path> --mode=corrupt --target=tip
//   v4_4_inject_undo_corruption <datadir-path> --mode=delete --target=middle
//
//   --mode=delete    removes one "undo_<hash>" entry → expected detection
//                    cause="missing"
//   --mode=corrupt   flips one byte inside one "undo_<hash>" entry's payload
//                    (NOT the trailing 32-byte SHA3 checksum) → expected
//                    detection cause="checksum_mismatch"
//
//   --target=tip     read "bestblock" from <datadir>/blocks/ (the blockchain
//                    DB) and target the tip block's undo entry. Walk hits
//                    this on the FIRST pprev iteration. GUARANTEED in-window.
//   --target=middle  pick the middle "undo_<hash>" entry by LevelDB byte-order
//                    index. NOT height-ordered; with N total entries vs
//                    M in-window, only M/N chance of being in-window.
//
// Reports the target hash to stderr/stdout so the test harness can
// cross-reference against the v4.4 binary's failure log.
//
// MUST run against a COPY of the chainstate (LevelDB single-writer); never
// against a live datadir.

#include <leveldb/db.h>
#include <leveldb/options.h>
#include <leveldb/slice.h>
#include <leveldb/write_batch.h>

#include <cstdio>
#include <cstring>
#include <iostream>
#include <memory>
#include <string>

namespace {

constexpr const char* kUndoPrefix = "undo_";
constexpr size_t kUndoPrefixLen = 5;
constexpr size_t kHashLen = 32;
constexpr size_t kKeyLen = kUndoPrefixLen + kHashLen;
constexpr size_t kChecksumLen = 32;

bool StartsWithUndoPrefix(const leveldb::Slice& key) {
    return key.size() == kKeyLen
        && std::memcmp(key.data(), kUndoPrefix, kUndoPrefixLen) == 0;
}

std::string HexEncode(const char* data, size_t len) {
    std::string out;
    out.reserve(len * 2);
    char buf[3];
    for (size_t i = 0; i < len; ++i) {
        std::snprintf(buf, sizeof buf, "%02x", static_cast<unsigned char>(data[i]));
        out.append(buf, 2);
    }
    return out;
}

// Decode 64-char hex into 32 raw bytes. Returns true on success.
bool HexDecode32(const std::string& hex, char out[32]) {
    if (hex.size() != 64) return false;
    auto nibble = [](char c) -> int {
        if (c >= '0' && c <= '9') return c - '0';
        if (c >= 'a' && c <= 'f') return c - 'a' + 10;
        if (c >= 'A' && c <= 'F') return c - 'A' + 10;
        return -1;
    };
    for (int i = 0; i < 32; ++i) {
        int hi = nibble(hex[2*i]);
        int lo = nibble(hex[2*i + 1]);
        if (hi < 0 || lo < 0) return false;
        out[i] = static_cast<char>((hi << 4) | lo);
    }
    return true;
}

// Read the "bestblock" key from <datadir>/blocks/ blockchain DB.
// Stored as hex string per blockchain_storage.cpp:932 batch.Put("bestblock", hash.GetHex()).
bool ReadBestBlockHashHex(const std::string& datadir, std::string& out_hex) {
    const std::string blocks_path = datadir + "/blocks";
    leveldb::DB* db = nullptr;
    leveldb::Options opts;
    opts.create_if_missing = false;
    leveldb::Status st = leveldb::DB::Open(opts, blocks_path, &db);
    if (!st.ok()) {
        std::cerr << "Failed to open blockchain DB at " << blocks_path
                  << ": " << st.ToString() << "\n";
        return false;
    }
    st = db->Get(leveldb::ReadOptions(), "bestblock", &out_hex);
    delete db;
    if (!st.ok()) {
        std::cerr << "Failed to read 'bestblock' key: " << st.ToString() << "\n";
        return false;
    }
    return true;
}

}  // namespace

int main(int argc, char** argv) {
    if (argc != 4) {
        std::cerr << "Usage: " << argv[0]
                  << " <datadir-path> --mode=delete|corrupt --target=tip|middle\n";
        return 1;
    }

    const std::string datadir = argv[1];
    const std::string mode_arg = argv[2];
    const std::string target_arg = argv[3];

    bool mode_delete = false;
    bool mode_corrupt = false;
    if (mode_arg == "--mode=delete") mode_delete = true;
    else if (mode_arg == "--mode=corrupt") mode_corrupt = true;
    else {
        std::cerr << "Unknown mode: " << mode_arg << "\n";
        return 1;
    }

    bool target_tip = false;
    bool target_middle = false;
    if (target_arg == "--target=tip") target_tip = true;
    else if (target_arg == "--target=middle") target_middle = true;
    else {
        std::cerr << "Unknown target: " << target_arg << "\n";
        return 1;
    }

    const std::string chainstate_path = datadir + "/chainstate";

    leveldb::DB* db = nullptr;
    leveldb::Options opts;
    opts.create_if_missing = false;
    leveldb::Status st = leveldb::DB::Open(opts, chainstate_path, &db);
    if (!st.ok()) {
        std::cerr << "Failed to open chainstate at " << chainstate_path
                  << ": " << st.ToString() << "\n";
        return 1;
    }

    std::string target_key;
    std::string target_value;
    std::string target_hash_hex;

    if (target_tip) {
        // Read bestblock hash from blockchain DB.
        if (!ReadBestBlockHashHex(datadir, target_hash_hex)) {
            delete db;
            return 1;
        }
        std::cerr << "Tip hash from bestblock (display order): "
                  << target_hash_hex << "\n";

        // Convert hex → 32 raw bytes (display order — hex walks data[31]..data[0]).
        char hash_display[32];
        if (!HexDecode32(target_hash_hex, hash_display)) {
            std::cerr << "Failed to decode tip hash hex (expected 64 hex chars, got "
                      << target_hash_hex.size() << ")\n";
            delete db;
            return 1;
        }

        // Reverse to internal byte order — undo_ keys use the raw uint256::data
        // forward order, while GetHex() produces display order (data[31]..data[0]).
        // See src/primitives/block.cpp uint256::GetHex().
        char hash_internal[32];
        for (int i = 0; i < 32; ++i) hash_internal[i] = hash_display[31 - i];

        target_key.assign(kUndoPrefix, kUndoPrefixLen);
        target_key.append(hash_internal, kHashLen);

        // Verify this entry exists in chainstate.
        st = db->Get(leveldb::ReadOptions(), target_key, &target_value);
        if (!st.ok()) {
            std::cerr << "No undo entry for tip hash in chainstate (after byte reverse): "
                      << st.ToString() << "\n";
            std::cerr << "Trying without byte reverse as fallback...\n";
            target_key.assign(kUndoPrefix, kUndoPrefixLen);
            target_key.append(hash_display, kHashLen);
            st = db->Get(leveldb::ReadOptions(), target_key, &target_value);
            if (!st.ok()) {
                std::cerr << "Still not found: " << st.ToString() << "\n";
                delete db;
                return 1;
            }
            std::cerr << "Found via NON-reversed bytes (display-order undo key)\n";
        } else {
            std::cerr << "Found via reversed bytes (internal-order undo key)\n";
        }
        std::cerr << "Tip undo entry size: " << target_value.size()
                  << " bytes (will hit on first pprev iteration of v4.4 walk)\n";
    } else if (target_middle) {
        // Phase 1: count undo_* entries to pick the middle index.
        int count = 0;
        {
            std::unique_ptr<leveldb::Iterator> it(
                db->NewIterator(leveldb::ReadOptions()));
            for (it->Seek(kUndoPrefix);
                 it->Valid() && StartsWithUndoPrefix(it->key());
                 it->Next()) {
                ++count;
            }
        }

        if (count == 0) {
            std::cerr << "No undo_* entries found in " << chainstate_path << "\n";
            delete db;
            return 1;
        }

        const int target_idx = count / 2;
        std::cerr << "Found " << count << " undo entries; targeting index "
                  << target_idx << " (middle by LevelDB byte order, not height)\n";

        // Phase 2: capture the target key + value.
        std::unique_ptr<leveldb::Iterator> it(
            db->NewIterator(leveldb::ReadOptions()));
        int idx = 0;
        for (it->Seek(kUndoPrefix);
             it->Valid() && StartsWithUndoPrefix(it->key());
             it->Next()) {
            if (idx == target_idx) {
                target_key.assign(it->key().data(), it->key().size());
                target_value.assign(it->value().data(), it->value().size());
                break;
            }
            ++idx;
        }

        if (target_key.empty()) {
            std::cerr << "Failed to capture target key at index " << target_idx << "\n";
            delete db;
            return 1;
        }

        target_hash_hex =
            HexEncode(target_key.data() + kUndoPrefixLen, kHashLen);
        std::cerr << "Target undo entry hash (hex, big-endian byte order): "
                  << target_hash_hex << "\n";
        std::cerr << "Target undo value size: " << target_value.size() << " bytes\n";
    }

    // Phase 3: apply mutation.
    leveldb::WriteOptions wopts;
    wopts.sync = true;

    if (mode_delete) {
        st = db->Delete(wopts, target_key);
        if (!st.ok()) {
            std::cerr << "Delete failed: " << st.ToString() << "\n";
            delete db;
            return 1;
        }
        std::cerr << "DELETED undo entry. Expected v4.4 detection: cause=\"missing\"\n";
    } else if (mode_corrupt) {
        // Flip a bit inside the payload (NOT the trailing 32-byte SHA3 checksum).
        // Pick offset 1 (inside the 4-byte spentCount field at the start of the
        // payload). This matches CUTXOSet::CorruptUndoForTesting's semantic.
        if (target_value.size() < kChecksumLen + 4) {
            std::cerr << "Target value too small to corrupt safely ("
                      << target_value.size() << " bytes, need >="
                      << (kChecksumLen + 4) << ")\n";
            delete db;
            return 1;
        }
        std::string corrupted = target_value;
        corrupted[1] = static_cast<char>(corrupted[1] ^ 0x80);

        st = db->Put(wopts, target_key, corrupted);
        if (!st.ok()) {
            std::cerr << "Put (corrupt) failed: " << st.ToString() << "\n";
            delete db;
            return 1;
        }
        std::cerr << "CORRUPTED undo entry (flipped byte 1, payload). "
                  << "Expected v4.4 detection: cause=\"checksum_mismatch\"\n";
    }

    delete db;
    std::cout << target_hash_hex << "\n";  // stdout: target hash for harness use
    return 0;
}
