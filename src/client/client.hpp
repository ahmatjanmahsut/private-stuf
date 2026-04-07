#pragma once
#include "common/config.hpp"
#include "tunnel/tunnel_manager.hpp"
#include "tun/itun.hpp"
#include <asio.hpp>
#include <atomic>
#include <cstddef>
#include <memory>
#include <thread>

namespace vpn {

class Client {
public:
    explicit Client(const Config& cfg);
    ~Client();

    void run();
    void stop();
    size_t session_count() const;


private:
    const Config&               cfg_;
    asio::io_context            io_ctx_;
    TunnelManager               tunnel_mgr_;
    std::unique_ptr<ITunDevice> tun_;
    std::atomic<bool>           running_{false};
    uint32_t                    session_id_ = 0;
    std::shared_ptr<asio::ip::tcp::socket> sock_;

    bool connect_and_handshake();
    void recv_loop();
    void tun_read_loop();

    std::unique_ptr<ICrypto> make_crypto() const;
};

} // namespace vpn
