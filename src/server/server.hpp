#pragma once
#include "common/config.hpp"
#include "tunnel/tunnel_manager.hpp"
#include "tun/itun.hpp"
#include <asio.hpp>
#include <atomic>
#include <cstddef>
#include <memory>
#include <mutex>
#include <thread>
#include <unordered_map>
#include <vector>

namespace vpn {

class Server {
public:
    explicit Server(const Config& cfg);
    ~Server();

    void run();
    void stop();
    size_t session_count() const;

private:

    const Config&               cfg_;
    asio::io_context            io_ctx_;
    asio::ip::tcp::acceptor     acceptor_;
    TunnelManager               tunnel_mgr_;
    std::unique_ptr<ITunDevice> tun_;
    std::vector<std::thread>    workers_;
    std::atomic<bool>           running_{false};


    // session_id -> TCP socket（用于 TUN→隧道 方向路由）
    std::mutex sessions_sock_mutex_;
    std::unordered_map<uint32_t,
        std::shared_ptr<asio::ip::tcp::socket>> session_socks_;

    void register_session_sock(uint32_t sid,
        std::shared_ptr<asio::ip::tcp::socket> sock);
    void unregister_session_sock(uint32_t sid);

    void start_accept();
    void handle_client(std::shared_ptr<asio::ip::tcp::socket> sock);
    void handle_handshake(std::shared_ptr<asio::ip::tcp::socket> sock);
    void run_session(std::shared_ptr<asio::ip::tcp::socket> sock,
                     uint32_t session_id);
    void tun_read_loop();

    std::unique_ptr<ICrypto> make_crypto() const;
};

} // namespace vpn
