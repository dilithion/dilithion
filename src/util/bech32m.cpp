// Copyright (c) 2025 The Dilithion Core developers
// Distributed under the MIT software license
//
// bech32m (BIP350) codec — ported/adapted from Bitcoin Core's bech32.cpp
// (Copyright (c) 2017/2019 Pieter Wuille, MIT). The polymod, hrp-expansion,
// charset and general structure are the upstream reference; the checksum
// constant is fixed to bech32m's 0x2bc830a3 (Dilithion ION uses bech32m only).

#include "bech32m.h"

#include <cstring>

namespace bech32m {

namespace {

// The bech32/bech32m character set for encoding (BIP173/BIP350).
const char* CHARSET = "qpzry9x8gf2tvdw0s3jn54khce6mua7l";

// Reverse lookup: character -> 5-bit value, or -1 if not in the charset.
// Rows for 'A'-'Z' and 'a'-'z' are identical so both cases map correctly;
// mixed case is rejected separately before this table is consulted.
const int8_t CHARSET_REV[128] = {
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    15, -1, 10, 17, 21, 20, 26, 30,  7,  5, -1, -1, -1, -1, -1, -1,
    -1, 29, -1, 24, 13, 25,  9,  8, 23, -1, 18, 22, 31, 27, 19, -1,
     1,  0,  3, 16, 11, 28, 12, 14,  6,  4,  2, -1, -1, -1, -1, -1,
    -1, 29, -1, 24, 13, 25,  9,  8, 23, -1, 18, 22, 31, 27, 19, -1,
     1,  0,  3, 16, 11, 28, 12, 14,  6,  4,  2, -1, -1, -1, -1, -1
};

// Concatenate the expanded HRP with the values and compute the BCH residue mod
// the bech32/bech32m generator (upstream Bitcoin Core PolyMod).
uint32_t PolyMod(const std::vector<uint8_t>& v) {
    uint32_t c = 1;
    for (const auto v_i : v) {
        uint8_t c0 = c >> 25;
        c = ((c & 0x1ffffff) << 5) ^ v_i;
        if (c0 & 1)  c ^= 0x3b6a57b2;
        if (c0 & 2)  c ^= 0x26508e6d;
        if (c0 & 4)  c ^= 0x1ea119fa;
        if (c0 & 8)  c ^= 0x3d4233dd;
        if (c0 & 16) c ^= 0x2a1462b3;
    }
    return c;
}

// Expand a HRP for use in checksum computation (upstream ExpandHRP).
std::vector<uint8_t> ExpandHRP(const std::string& hrp) {
    std::vector<uint8_t> ret(hrp.size() * 2 + 1);
    for (size_t i = 0; i < hrp.size(); ++i) {
        unsigned char c = static_cast<unsigned char>(hrp[i]);
        ret[i] = c >> 5;
        ret[i + hrp.size() + 1] = c & 0x1f;
    }
    ret[hrp.size()] = 0;
    return ret;
}

// Verify the bech32m checksum over (hrp, values) where values INCLUDES the
// 6-symbol checksum.
bool VerifyChecksum(const std::string& hrp, const std::vector<uint8_t>& values) {
    std::vector<uint8_t> enc = ExpandHRP(hrp);
    enc.insert(enc.end(), values.begin(), values.end());
    return PolyMod(enc) == BECH32M_CONST;
}

// Compute the 6-symbol bech32m checksum for (hrp, values).
std::vector<uint8_t> CreateChecksum(const std::string& hrp, const std::vector<uint8_t>& values) {
    std::vector<uint8_t> enc = ExpandHRP(hrp);
    enc.insert(enc.end(), values.begin(), values.end());
    enc.resize(enc.size() + 6);  // append 6 zero symbols
    uint32_t mod = PolyMod(enc) ^ BECH32M_CONST;
    std::vector<uint8_t> ret(6);
    for (size_t i = 0; i < 6; ++i) {
        ret[i] = (mod >> (5 * (5 - i))) & 31;
    }
    return ret;
}

} // namespace

bool ConvertBits(std::vector<uint8_t>& out, const std::vector<uint8_t>& in,
                 int frombits, int tobits, bool pad) {
    int acc = 0;
    int bits = 0;
    const int maxv = (1 << tobits) - 1;
    const int max_acc = (1 << (frombits + tobits - 1)) - 1;
    for (const uint8_t value : in) {
        if ((value >> frombits) != 0) {
            return false;  // value has bits set beyond `frombits`
        }
        acc = ((acc << frombits) | value) & max_acc;
        bits += frombits;
        while (bits >= tobits) {
            bits -= tobits;
            out.push_back((acc >> bits) & maxv);
        }
    }
    if (pad) {
        if (bits) {
            out.push_back((acc << (tobits - bits)) & maxv);
        }
    } else if (bits >= frombits || ((acc << (tobits - bits)) & maxv)) {
        return false;  // leftover bits, or non-zero padding — not a clean encode
    }
    return true;
}

std::string Encode(const std::string& hrp, const std::vector<uint8_t>& values) {
    // HRP must be non-empty, printable-ASCII, and NOT contain uppercase (we only
    // ever emit lowercase bech32m).
    if (hrp.empty()) {
        return "";
    }
    for (const char ch : hrp) {
        unsigned char c = static_cast<unsigned char>(ch);
        if (c < 33 || c > 126) return "";
        if (c >= 'A' && c <= 'Z') return "";
    }
    std::vector<uint8_t> checksum = CreateChecksum(hrp, values);
    std::vector<uint8_t> combined = values;
    combined.insert(combined.end(), checksum.begin(), checksum.end());

    std::string ret;
    ret.reserve(hrp.size() + 1 + combined.size());
    ret += hrp;
    ret += '1';
    for (const uint8_t c : combined) {
        if (c >> 5) return "";  // not a valid 5-bit value
        ret += CHARSET[c];
    }
    return ret;
}

DecodeResult Decode(const std::string& str) {
    DecodeResult res;

    // Reject over-length input (BIP173 caps bech32 strings at 90 chars).
    if (str.size() > 90 || str.empty()) {
        return res;
    }

    // Case check: everything must be printable ASCII, and the string must not
    // mix upper and lower case.
    bool lower = false, upper = false;
    for (const char ch : str) {
        unsigned char c = static_cast<unsigned char>(ch);
        if (c < 33 || c > 126) return res;
        if (c >= 'a' && c <= 'z') lower = true;
        if (c >= 'A' && c <= 'Z') upper = true;
    }
    if (lower && upper) {
        return res;  // mixed case forbidden
    }

    // Separator is the LAST '1'.
    const size_t pos = str.rfind('1');
    if (pos == std::string::npos || pos == 0 || pos + 7 > str.size()) {
        // No separator, empty HRP, or fewer than 6 checksum symbols after it.
        return res;
    }

    // Decode the data part (post-separator) into 5-bit values.
    std::vector<uint8_t> values(str.size() - 1 - pos);
    for (size_t i = 0; i < values.size(); ++i) {
        unsigned char c = static_cast<unsigned char>(str[i + pos + 1]);
        int8_t rev = (c < 128) ? CHARSET_REV[c] : -1;
        if (rev == -1) {
            return res;  // char not in the bech32 charset
        }
        values[i] = static_cast<uint8_t>(rev);
    }

    // Lowercase the HRP for a canonical, case-insensitive result.
    std::string hrp = str.substr(0, pos);
    for (char& ch : hrp) {
        if (ch >= 'A' && ch <= 'Z') ch += ('a' - 'A');
    }

    if (!VerifyChecksum(hrp, values)) {
        return res;  // bad checksum
    }

    // Strip the trailing 6 checksum symbols.
    res.hrp = std::move(hrp);
    res.data.assign(values.begin(), values.end() - 6);
    res.ok = true;
    return res;
}

} // namespace bech32m
