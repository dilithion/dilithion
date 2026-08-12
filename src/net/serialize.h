// Copyright (c) 2025 The Dilithion Core developers
// Distributed under the MIT software license

#ifndef DILITHION_NET_SERIALIZE_H
#define DILITHION_NET_SERIALIZE_H

#include <primitives/block.h>
#include <primitives/transaction.h>   // CompactSizeIsCanonical — shared minimality rule
#include <net/protocol.h>
#include <vector>
#include <string>
#include <cstring>
#include <stdexcept>

/**
 * CDataStream - Binary serialization buffer for network messages
 *
 * Provides read/write operations for primitive types and structured data.
 * Used for encoding/decoding network protocol messages.
 */
class CDataStream {
private:
    std::vector<uint8_t> data;
    size_t read_pos;

public:
    CDataStream() : read_pos(0) {}

    CDataStream(const std::vector<uint8_t>& data_in)
        : data(data_in), read_pos(0) {}

    CDataStream(const uint8_t* begin, const uint8_t* end)
        : data(begin, end), read_pos(0) {}

    // Clear the stream
    void clear() {
        data.clear();
        read_pos = 0;
    }

    // Get size of data
    size_t size() const { return data.size(); }

    // Check if at end
    bool eof() const { return read_pos >= data.size(); }

    // Get remaining bytes
    size_t remaining() const {
        return read_pos < data.size() ? data.size() - read_pos : 0;
    }

    // Get read position
    size_t tell() const { return read_pos; }

    // Seek to position
    void seek(size_t pos) { read_pos = pos; }

    // Get raw data
    const std::vector<uint8_t>& GetData() const { return data; }
    const uint8_t* data_ptr() const { return data.data(); }

    // Reserve space
    void reserve(size_t n) { data.reserve(n); }

    // --- Write Operations ---

    // Write raw bytes
    void write(const uint8_t* src, size_t len) {
        data.insert(data.end(), src, src + len);
    }

    void write(const std::vector<uint8_t>& src) {
        data.insert(data.end(), src.begin(), src.end());
    }

    // Write primitive types (little-endian)
    void WriteUint8(uint8_t value) {
        data.push_back(value);
    }

    void WriteUint16(uint16_t value) {
        uint8_t buf[2];
        buf[0] = value & 0xff;
        buf[1] = (value >> 8) & 0xff;
        write(buf, 2);
    }

    void WriteUint32(uint32_t value) {
        uint8_t buf[4];
        buf[0] = value & 0xff;
        buf[1] = (value >> 8) & 0xff;
        buf[2] = (value >> 16) & 0xff;
        buf[3] = (value >> 24) & 0xff;
        write(buf, 4);
    }

    void WriteUint64(uint64_t value) {
        uint8_t buf[8];
        for (int i = 0; i < 8; i++) {
            buf[i] = (value >> (i * 8)) & 0xff;
        }
        write(buf, 8);
    }

    void WriteInt32(int32_t value) {
        WriteUint32(static_cast<uint32_t>(value));
    }

    void WriteInt64(int64_t value) {
        WriteUint64(static_cast<uint64_t>(value));
    }

    // Write variable-length integer (CompactSize)
    void WriteCompactSize(uint64_t value) {
        if (value < 253) {
            WriteUint8(static_cast<uint8_t>(value));
        } else if (value <= 0xFFFF) {
            WriteUint8(253);
            WriteUint16(static_cast<uint16_t>(value));
        } else if (value <= 0xFFFFFFFF) {
            WriteUint8(254);
            WriteUint32(static_cast<uint32_t>(value));
        } else {
            WriteUint8(255);
            WriteUint64(value);
        }
    }

    // Write string
    void WriteString(const std::string& str) {
        WriteCompactSize(str.size());
        write(reinterpret_cast<const uint8_t*>(str.data()), str.size());
    }

    // Write uint256
    void WriteUint256(const uint256& hash) {
        write(hash.data, 32);
    }

    // --- Read Operations ---

    // Read raw bytes
    void read(uint8_t* dst, size_t len) {
        if (read_pos + len > data.size()) {
            throw std::runtime_error("CDataStream: read past end");
        }
        memcpy(dst, &data[read_pos], len);
        read_pos += len;
    }

    std::vector<uint8_t> read(size_t len) {
        if (read_pos + len > data.size()) {
            throw std::runtime_error("CDataStream: read past end");
        }
        std::vector<uint8_t> result(data.begin() + read_pos,
                                    data.begin() + read_pos + len);
        read_pos += len;
        return result;
    }

    // Read primitive types
    uint8_t ReadUint8() {
        if (read_pos >= data.size()) {
            throw std::runtime_error("CDataStream: read past end");
        }
        return data[read_pos++];
    }

    uint16_t ReadUint16() {
        uint8_t buf[2];
        read(buf, 2);
        return static_cast<uint16_t>(buf[0]) |
               (static_cast<uint16_t>(buf[1]) << 8);
    }

    uint32_t ReadUint32() {
        uint8_t buf[4];
        read(buf, 4);
        return static_cast<uint32_t>(buf[0]) |
               (static_cast<uint32_t>(buf[1]) << 8) |
               (static_cast<uint32_t>(buf[2]) << 16) |
               (static_cast<uint32_t>(buf[3]) << 24);
    }

    uint64_t ReadUint64() {
        uint8_t buf[8];
        read(buf, 8);
        uint64_t result = 0;
        for (int i = 0; i < 8; i++) {
            result |= static_cast<uint64_t>(buf[i]) << (i * 8);
        }
        return result;
    }

    int32_t ReadInt32() {
        return static_cast<int32_t>(ReadUint32());
    }

    int64_t ReadInt64() {
        return static_cast<int64_t>(ReadUint64());
    }

    // Read variable-length integer.
    // Malleability finding #5: enforce minimal (shortest-form) encoding so a
    // single value has exactly one wire byte-string. Uses the same shared range
    // check (CompactSizeIsCanonical) as the other two decoders — no drift.
    uint64_t ReadCompactSize() {
        uint8_t first = ReadUint8();
        uint64_t value;
        if (first < 253) {
            value = first;
        } else if (first == 253) {
            value = ReadUint16();
        } else if (first == 254) {
            value = ReadUint32();
        } else {
            value = ReadUint64();
        }
        if (!CompactSizeIsCanonical(first, value)) {
            throw std::runtime_error("Non-canonical CompactSize (non-minimal encoding)");
        }
        return value;
    }

    // Read string
    // NET-002 FIX: Reduce default limit to prevent DoS, add configurable limit
    std::string ReadString(size_t max_len = 256) {
        uint64_t len = ReadCompactSize();

        // NET-002 FIX: Much stricter limits to prevent memory exhaustion
        // Default 256 bytes for user agents, pass larger limit explicitly if needed
        // Absolute maximum: 10KB (prevents DoS from 1000s of 1MB allocations)
        if (len > 10 * 1024) {
            throw std::runtime_error("String exceeds absolute limit (10KB)");
        }

        if (len > max_len) {
            throw std::runtime_error("String too large for context");
        }

        std::vector<uint8_t> buf = read(len);
        return std::string(buf.begin(), buf.end());
    }

    // Read uint256
    uint256 ReadUint256() {
        uint256 result;
        read(result.data, 32);
        return result;
    }

    // --- Helper Functions ---

    // Serialize message header
    static std::vector<uint8_t> SerializeHeader(
        const NetProtocol::CMessageHeader& header)
    {
        CDataStream stream;
        stream.WriteUint32(header.magic);
        stream.write(reinterpret_cast<const uint8_t*>(header.command), 12);
        stream.WriteUint32(header.payload_size);
        stream.WriteUint32(header.checksum);
        return stream.GetData();
    }

    // Deserialize message header
    static NetProtocol::CMessageHeader DeserializeHeader(
        const std::vector<uint8_t>& data)
    {
        if (data.size() < 24) {
            throw std::runtime_error("Header too small");
        }

        CDataStream stream(data);
        NetProtocol::CMessageHeader header;
        header.magic = stream.ReadUint32();
        stream.read(reinterpret_cast<uint8_t*>(header.command), 12);
        header.payload_size = stream.ReadUint32();
        header.checksum = stream.ReadUint32();

        return header;
    }

    // Calculate checksum (first 4 bytes of double SHA256)
    static uint32_t CalculateChecksum(const std::vector<uint8_t>& data);
};

/**
 * CNetMessage - Complete network message with header and payload
 */
class CNetMessage {
public:
    NetProtocol::CMessageHeader header;
    std::vector<uint8_t> payload;

    CNetMessage() {}

    CNetMessage(const std::string& command, const std::vector<uint8_t>& payload_in)
        : payload(payload_in)
    {
        header.magic = NetProtocol::g_network_magic;
        header.SetCommand(command);
        header.payload_size = payload.size();
        header.checksum = CDataStream::CalculateChecksum(payload);
    }

    // Get total message size
    size_t GetTotalSize() const {
        // NET-001 FIX: Check for integer overflow before addition
        // If payload.size() > SIZE_MAX - 24, addition would overflow
        const size_t header_size = 24;
        size_t payload_sz = payload.size();

        // Check if addition would overflow
        if (payload_sz > SIZE_MAX - header_size) {
            throw std::runtime_error("Message size overflow: payload too large");
        }

        return header_size + payload_sz;
    }

    // Serialize to bytes
    std::vector<uint8_t> Serialize() const {
        std::vector<uint8_t> result = CDataStream::SerializeHeader(header);
        result.insert(result.end(), payload.begin(), payload.end());
        return result;
    }

    // Validate message
    bool IsValid() const {
        if (!header.IsValid(NetProtocol::g_network_magic)) {
            return false;
        }
        if (payload.size() != header.payload_size) {
            return false;
        }
        uint32_t calc_checksum = CDataStream::CalculateChecksum(payload);
        return calc_checksum == header.checksum;
    }
};

#endif // DILITHION_NET_SERIALIZE_H
