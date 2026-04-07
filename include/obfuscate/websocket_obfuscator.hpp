#pragma once
#include "iobfuscator.hpp"

namespace vpn {

// 按 RFC 6455 封装 WebSocket 二进制帧（含 masking），接收端拆帧还原
class WebSocketObfuscator : public IObfuscator {
public:
    std::vector<uint8_t> obfuscate(const std::vector<uint8_t>& data) override;
    std::vector<uint8_t> deobfuscate(const std::vector<uint8_t>& data) override;
    const char* name() const override { return "WebSocket"; }

private:
    // 生成 4 字节随机 masking key
    static std::array<uint8_t, 4> random_mask();
    // 对数据做 XOR masking/unmasking
    static std::vector<uint8_t> apply_mask(const std::vector<uint8_t>& data,
                                            const std::array<uint8_t, 4>& mask);
};

} // namespace vpn
