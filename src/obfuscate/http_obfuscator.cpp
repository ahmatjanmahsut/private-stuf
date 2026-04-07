#include "obfuscate/http_obfuscator.hpp"
#include <sstream>
#include <stdexcept>
#include <cstring>

namespace vpn {

HttpObfuscator::HttpObfuscator(std::string host, std::string path)
    : host_(std::move(host)), path_(std::move(path)) {}

// 发送：将数据包装为 HTTP POST 请求
// 格式：
//   POST /path HTTP/1.1\r\n
//   Host: host\r\n
//   Content-Type: application/octet-stream\r\n
//   Content-Length: <len>\r\n
//   \r\n
//   <data>
std::vector<uint8_t> HttpObfuscator::obfuscate(const std::vector<uint8_t>& data) {
    std::ostringstream hdr;
    hdr << "POST " << path_ << " HTTP/1.1\r\n"
        << "Host: " << host_ << "\r\n"
        << "Content-Type: application/octet-stream\r\n"
        << "Content-Length: " << data.size() << "\r\n"
        << "\r\n";
    std::string h = hdr.str();

    std::vector<uint8_t> out;
    out.reserve(h.size() + data.size());
    out.insert(out.end(), h.begin(), h.end());
    out.insert(out.end(), data.begin(), data.end());
    return out;
}

// 接收：剥除 HTTP 头，返回 body
std::vector<uint8_t> HttpObfuscator::deobfuscate(const std::vector<uint8_t>& data) {
    // 查找 \r\n\r\n
    const char* needle = "\r\n\r\n";
    const uint8_t* p = data.data();
    size_t n = data.size();

    for (size_t i = 0; i + 3 < n; ++i) {
        if (p[i] == '\r' && p[i+1] == '\n' && p[i+2] == '\r' && p[i+3] == '\n') {
            size_t body_start = i + 4;
            return std::vector<uint8_t>(p + body_start, p + n);
        }
    }
    // 找不到分隔符，原样返回（容错）
    return data;
}

} // namespace vpn
