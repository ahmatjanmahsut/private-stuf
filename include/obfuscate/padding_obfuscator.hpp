#pragma once
#include "iobfuscator.hpp"

namespace vpn {

// 在数据包尾追加随机 padding，包头记录原始长度；发包时可加随机时延
class PaddingObfuscator : public IObfuscator {
public:
    // max_pad: 最大填充字节数（0~255）
    // delay_us_max: 最大随机延迟微秒（0 表示不延迟）
    explicit PaddingObfuscator(int max_pad = 255, int delay_us_max = 5000);

    std::vector<uint8_t> obfuscate(const std::vector<uint8_t>& data) override;
    std::vector<uint8_t> deobfuscate(const std::vector<uint8_t>& data) override;
    const char* name() const override { return "Padding"; }

private:
    int max_pad_;
    int delay_us_max_;
};

} // namespace vpn
