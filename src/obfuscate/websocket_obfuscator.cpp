#include "obfuscate/websocket_obfuscator.hpp"
#include <openssl/rand.h>
#include <stdexcept>
#include <cstring>
#include <array>

namespace vpn {

// RFC 6455 二进制帧（opcode=0x02），FIN=1，MASK=1（客户端方向）
// 帧格式：
//  byte0: 0x82 (FIN=1, opcode=2 binary)
//  byte1: 0x80|payload_len  (MASK=1, payload_len < 126)
//      or 0x80|126, len16[2], mask[4], data
//      or 0x80|127, len64[8], mask[4], data

std::array<uint8_t, 4> WebSocketObfuscator::random_mask() {
    std::array<uint8_t, 4> mask{};
    RAND_bytes(mask.data(), 4);
    return mask;
}

std::vector<uint8_t> WebSocketObfuscator::apply_mask(const std::vector<uint8_t>& data,
                                                       const std::array<uint8_t, 4>& mask) {
    std::vector<uint8_t> out(data.size());
    for (size_t i = 0; i < data.size(); ++i)
        out[i] = data[i] ^ mask[i % 4];
    return out;
}

std::vector<uint8_t> WebSocketObfuscator::obfuscate(const std::vector<uint8_t>& data) {
    auto mask    = random_mask();
    auto masked  = apply_mask(data, mask);
    size_t plen  = data.size();

    std::vector<uint8_t> frame;
    frame.reserve(2 + 8 + 4 + plen);

    frame.push_back(0x82); // FIN + binary

    if (plen < 126) {
        frame.push_back(static_cast<uint8_t>(0x80 | plen));
    } else if (plen < 65536) {
        frame.push_back(0x80 | 126);
        frame.push_back(static_cast<uint8_t>((plen >> 8) & 0xff));
        frame.push_back(static_cast<uint8_t>(plen & 0xff));
    } else {
        frame.push_back(0x80 | 127);
        for (int i = 7; i >= 0; --i)
            frame.push_back(static_cast<uint8_t>((plen >> (8 * i)) & 0xff));
    }

    frame.insert(frame.end(), mask.begin(), mask.end());
    frame.insert(frame.end(), masked.begin(), masked.end());
    return frame;
}

std::vector<uint8_t> WebSocketObfuscator::deobfuscate(const std::vector<uint8_t>& data) {
    if (data.size() < 6) return data; // too short, pass through

    size_t pos = 0;
    /*uint8_t byte0 =*/ data[pos++]; // FIN+opcode, skip
    uint8_t byte1 = data[pos++];

    bool masked     = (byte1 & 0x80) != 0;
    uint64_t plen   = byte1 & 0x7f;

    if (plen == 126) {
        if (data.size() < pos + 2) return data;
        plen = (static_cast<uint64_t>(data[pos]) << 8) | data[pos+1];
        pos += 2;
    } else if (plen == 127) {
        if (data.size() < pos + 8) return data;
        plen = 0;
        for (int i = 0; i < 8; ++i)
            plen = (plen << 8) | data[pos + i];
        pos += 8;
    }

    std::array<uint8_t, 4> mask{};
    if (masked) {
        if (data.size() < pos + 4) return data;
        mask[0] = data[pos]; mask[1] = data[pos+1];
        mask[2] = data[pos+2]; mask[3] = data[pos+3];
        pos += 4;
    }

    if (data.size() < pos + plen) return data;

    std::vector<uint8_t> payload(data.begin() + pos, data.begin() + pos + plen);
    if (masked)
        payload = apply_mask(payload, mask);

    return payload;
}

} // namespace vpn
