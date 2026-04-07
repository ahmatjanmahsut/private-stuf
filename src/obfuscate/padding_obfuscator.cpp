#include "obfuscate/padding_obfuscator.hpp"
#include <openssl/rand.h>
#include <cstring>
#include <thread>
#include <chrono>
#include <stdexcept>

namespace vpn {

// 格式：[原始长度 4字节 LE][原始数据][随机 padding]
PaddingObfuscator::PaddingObfuscator(int max_pad, int delay_us_max)
    : max_pad_(max_pad), delay_us_max_(delay_us_max) {}

std::vector<uint8_t> PaddingObfuscator::obfuscate(const std::vector<uint8_t>& data) {
    // 随机 padding 长度
    uint8_t rand_byte = 0;
    RAND_bytes(&rand_byte, 1);
    int pad_len = max_pad_ > 0 ? (rand_byte % (max_pad_ + 1)) : 0;

    uint32_t orig_len = static_cast<uint32_t>(data.size());
    std::vector<uint8_t> out;
    out.reserve(4 + orig_len + pad_len);

    // 4 字节原始长度（little-endian）
    out.push_back(static_cast<uint8_t>(orig_len & 0xff));
    out.push_back(static_cast<uint8_t>((orig_len >> 8) & 0xff));
    out.push_back(static_cast<uint8_t>((orig_len >> 16) & 0xff));
    out.push_back(static_cast<uint8_t>((orig_len >> 24) & 0xff));

    out.insert(out.end(), data.begin(), data.end());

    // 随机填充
    if (pad_len > 0) {
        std::vector<uint8_t> pad(pad_len);
        RAND_bytes(pad.data(), pad_len);
        out.insert(out.end(), pad.begin(), pad.end());
    }

    // 流量整形：随机时延
    if (delay_us_max_ > 0) {
        uint32_t rnd = 0;
        RAND_bytes(reinterpret_cast<uint8_t*>(&rnd), sizeof(rnd));
        int delay_us = static_cast<int>(rnd % (delay_us_max_ + 1));
        if (delay_us > 0)
            std::this_thread::sleep_for(std::chrono::microseconds(delay_us));
    }

    return out;
}

std::vector<uint8_t> PaddingObfuscator::deobfuscate(const std::vector<uint8_t>& data) {
    if (data.size() < 4) return data;

    uint32_t orig_len =
        static_cast<uint32_t>(data[0]) |
        (static_cast<uint32_t>(data[1]) << 8) |
        (static_cast<uint32_t>(data[2]) << 16) |
        (static_cast<uint32_t>(data[3]) << 24);

    if (orig_len > data.size() - 4) return data; // 损坏包，原样返回

    return std::vector<uint8_t>(data.begin() + 4, data.begin() + 4 + orig_len);
}

} // namespace vpn
