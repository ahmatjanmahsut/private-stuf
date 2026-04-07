#pragma once
#include "iobfuscator.hpp"
#include <string>

namespace vpn {

// 将数据伪装为 HTTP POST 请求体（发送端），接收端剥除 HTTP 头还原数据
class HttpObfuscator : public IObfuscator {
public:
    explicit HttpObfuscator(std::string host = "www.example.com",
                            std::string path = "/api/data");

    std::vector<uint8_t> obfuscate(const std::vector<uint8_t>& data) override;
    std::vector<uint8_t> deobfuscate(const std::vector<uint8_t>& data) override;
    const char* name() const override { return "HTTP"; }

private:
    std::string host_;
    std::string path_;
};

} // namespace vpn
