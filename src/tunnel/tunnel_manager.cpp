#include "tunnel/tunnel_manager.hpp"
#include "obfuscate/http_obfuscator.hpp"
#include "obfuscate/websocket_obfuscator.hpp"
#include "obfuscate/padding_obfuscator.hpp"
#include "common/logger.hpp"

namespace vpn {

TunnelManager::TunnelManager(const Config& cfg) : cfg_(cfg) {}

uint32_t TunnelManager::create_session(
    std::unique_ptr<ICrypto> crypto,
    std::vector<std::shared_ptr<IObfuscator>> obfuscators)
{
    std::lock_guard<std::mutex> lk(sessions_mutex_);
    uint32_t sid = next_id_++;

    auto sess = std::make_unique<Session>();
    sess->session_id  = sid;
    sess->established = false;
    sess->crypto      = std::move(crypto);
    sess->obfuscators = std::move(obfuscators);

    sessions_[sid] = std::move(sess);
    VPN_INFO("TunnelManager: created session {}", sid);
    return sid;
}

Session* TunnelManager::get_session(uint32_t session_id) {
    std::lock_guard<std::mutex> lk(sessions_mutex_);
    auto it = sessions_.find(session_id);
    if (it == sessions_.end()) return nullptr;
    return it->second.get();
}

void TunnelManager::remove_session(uint32_t session_id) {
    std::lock_guard<std::mutex> lk(sessions_mutex_);
    sessions_.erase(session_id);
    VPN_INFO("TunnelManager: removed session {}", session_id);
}

void TunnelManager::cleanup_stale() {
    // Simple placeholder – in production track last_active timestamps
    (void)this;
}

size_t TunnelManager::session_count() const {
    std::lock_guard<std::mutex> lk(sessions_mutex_);
    return sessions_.size();
}

std::vector<std::shared_ptr<IObfuscator>>
TunnelManager::build_obfuscators(const std::vector<ObfuscateMode>& chain) {
    std::vector<std::shared_ptr<IObfuscator>> out;
    for (auto mode : chain) {
        switch (mode) {
            case ObfuscateMode::HTTP:
                out.push_back(std::make_shared<HttpObfuscator>());
                break;
            case ObfuscateMode::WEBSOCKET:
                out.push_back(std::make_shared<WebSocketObfuscator>());
                break;
            case ObfuscateMode::PADDING:
                out.push_back(std::make_shared<PaddingObfuscator>());
                break;
            default:
                break;
        }
    }
    return out;
}

} // namespace vpn
