#pragma once
#include "common/config.hpp"
#include "tunnel/tunnel_manager.hpp"
#include "tun/itun.hpp"
#include <asio.hpp>
#include <memory>
#include <thread>

namespace vpn {

class Server {
public:
    explicit Server(const Config& cfg);
    ~Server();

    void run();
    void stop();

private:
    const Config&               cfg_;
    asio::io_context            io_ctx_;
    asio::ip::tcp::acceptor     acceptor_;
    TunnelManager               tunnel_mgr_;
    std::unique_ptr<ITunDevice> tun_;
    std::vector<std::thread>    workers_;
    bool                        running_ = false;

    void start_accept();
    void handle_client(std::shared_ptr<asio::ip::tcp::socket> sock);
    void handle_handshake(std::shared_ptr<asio::ip::tcp::socket> sock);
    void run_session(std::shared_ptr<asio::ip::tcp::socket> sock, uint32_t session_id);
    void tun_read_loop();

    std::unique_ptr<ICrypto> make_crypto() const;
};

} // namespace vpn
