// Copyright (c) 2025 The Dilithion Core developers
// Distributed under the MIT software license
//
// WF-1: shared little-endian serialization helpers for Digital-DNA dimensions.
//
// The bytes emitted by each dimension's serialize() are SHA3-256'd into the
// on-chain dna_hash (committed to the coinbase scriptSig and re-hashed inside
// the registration-PoW consensus check). They therefore MUST be produced in a
// host-endianness-independent byte order or a big-endian node would compute a
// different dna_hash and reject an otherwise-valid registration block.
//
// These helpers write explicit little-endian (LSB first), byte-identical on
// little-endian hosts to the previous raw memcpy/reinterpret_cast copies, so no
// existing serialized DNA blob or dna_hash changes on current hardware. They
// mirror the write_u32/write_u64/write_double idiom already used in
// digital_dna.cpp / dna_verification.cpp.

#ifndef DILITHION_DIGITAL_DNA_DNA_SERIALIZE_H
#define DILITHION_DIGITAL_DNA_DNA_SERIALIZE_H

#include <cstdint>
#include <cstring>
#include <limits>
#include <vector>

namespace digital_dna {
namespace dna_le {

// Consensus double serialization reinterprets the double's bit pattern as a
// uint64 and writes it little-endian. That is only a stable, cross-host
// consensus encoding if double is IEEE-754 binary64. On an exotic FP host this
// would silently produce a different dna_hash and split the chain — turn it into
// a compile error instead.
static_assert(std::numeric_limits<double>::is_iec559 && sizeof(double) == 8,
              "consensus double serialization requires IEEE-754 binary64");

// ---- Appending writers (little-endian) ----

inline void put_u32(std::vector<uint8_t>& out, uint32_t v) {
    for (int i = 0; i < 4; i++) out.push_back(static_cast<uint8_t>(v >> (i * 8)));
}
inline void put_u64(std::vector<uint8_t>& out, uint64_t v) {
    for (int i = 0; i < 8; i++) out.push_back(static_cast<uint8_t>(v >> (i * 8)));
}
inline void put_i64(std::vector<uint8_t>& out, int64_t v) {
    put_u64(out, static_cast<uint64_t>(v));
}
inline void put_double(std::vector<uint8_t>& out, double v) {
    uint64_t bits;
    std::memcpy(&bits, &v, sizeof(double));  // bit-pattern reinterpret, then LE
    put_u64(out, bits);
}

// ---- Fixed-offset writers into a pre-sized buffer (little-endian) ----

inline void set_u32(uint8_t* dst, uint32_t v) {
    for (int i = 0; i < 4; i++) dst[i] = static_cast<uint8_t>(v >> (i * 8));
}
inline void set_u64(uint8_t* dst, uint64_t v) {
    for (int i = 0; i < 8; i++) dst[i] = static_cast<uint8_t>(v >> (i * 8));
}
inline void set_double(uint8_t* dst, double v) {
    uint64_t bits;
    std::memcpy(&bits, &v, sizeof(double));
    set_u64(dst, bits);
}

// ---- Readers (little-endian), for the deserialize round-trip ----

inline uint32_t get_u32(const uint8_t* src) {
    uint32_t v = 0;
    for (int i = 0; i < 4; i++) v |= static_cast<uint32_t>(src[i]) << (i * 8);
    return v;
}
inline uint64_t get_u64(const uint8_t* src) {
    uint64_t v = 0;
    for (int i = 0; i < 8; i++) v |= static_cast<uint64_t>(src[i]) << (i * 8);
    return v;
}
inline double get_double(const uint8_t* src) {
    uint64_t bits = get_u64(src);
    double v;
    std::memcpy(&v, &bits, sizeof(double));
    return v;
}

} // namespace dna_le
} // namespace digital_dna

#endif // DILITHION_DIGITAL_DNA_DNA_SERIALIZE_H
