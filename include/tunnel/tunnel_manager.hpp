#pragma once
#include "session.hpp"
#include "common/config.hpp"
#include <cstdint>
#include <memory>
#include <mutex>
#include <unordered_map>

namespace vpn {

class TunnelManager {
public:
    explicit TunnelManager(const Config& cfg);

    // 创建新会话，返回 session_id
    uint32_t create_session(std::unique_ptr<ICrypto> crypto,
                            std::vector<std::shared_ptr<IObfuscator>> obfuscators);

    // 获取已有会话（线程安全）
    Session* get_session(uint32_t session_id);

    // 删除会话
    void remove_session(uint32_t session_id);

    // 清理超时会话
    void cleanup_stale();

    size_t session_count() const;

private:
    const Config& cfg_;
    mutable std::mutex sessions_mutex_;
    std::unordered_map<uint32_t, std::unique_ptr<Session>> sessions_;
    uint32_t next_id_ = 1;

    // 构建混淆器链
    static std::vector<std::shared_ptr<IObfuscator>>
        build_obfuscators(const std::vector<ObfuscateMode>& chain);

    friend class Server;
    friend class Client;
};

} // namespace vpn
