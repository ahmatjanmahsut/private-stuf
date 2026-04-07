#pragma once
#include <cstdint>
#include <vector>

namespace vpn {

class IObfuscator {
public:
    virtual ~IObfuscator() = default;

    // 发送前调用：将净载荷包装为混淆后格式
    virtual std::vector<uint8_t> obfuscate(const std::vector<uint8_t>& data) = 0;

    // 接收后调用：从混淆格式还原净载荷
    virtual std::vector<uint8_t> deobfuscate(const std::vector<uint8_t>& data) = 0;

    virtual const char* name() const = 0;
};

} // namespace vpn
