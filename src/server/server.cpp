#include "server/server.hpp"
#include "common/logger.hpp"
#include "common/packet.hpp"
#include "crypto/chacha20_crypto.hpp"
#include "crypto/aes_gcm_crypto.hpp"
#include "tun/linux_tun.hpp"
#include <openssl/rand.h>
#include <openssl/hmac.h>
#include <cstring>

namespace vpn {

// ── 构造 ──────────────────────────────────────────────────────────────────
Server::Server(const Config& cfg)
    : cfg_(cfg),
      io_ctx_(),
      acceptor_(io_ctx_),
      tunnel_mgr_(cfg)
{
    // 创建 TUN 设备（Linux only）
    tun_ = std::make_unique<LinuxTun>();
    if (!tun_->open(cfg_.tun.name, cfg_.tun.address, cfg_.tun.netmask, cfg_.tun.mtu)) {
        throw std::runtime_error("Failed to open TUN device");
    }
    VPN_INFO("Server TUN: {} addr={}", cfg_.tun.name, cfg_.tun.address);
}

Server::~Server() { stop(); }

// ── 运行 ──────────────────────────────────────────────────────────────────
void Server::run() {
    running_ = true;

    // 监听 TCP
    asio::ip::tcp::endpoint ep(asio::ip::make_address(cfg_.listen_host), cfg_.listen_port);
    acceptor_.open(ep.protocol());
    acceptor_.set_option(asio::ip::tcp::acceptor::reuse_address(true));
    acceptor_.bind(ep);
    acceptor_.listen();
    VPN_INFO("Server listening on {}:{}", cfg_.listen_host, cfg_.listen_port);

    start_accept();

    // TUN 读取线程（从 TUN 读包 → 找到对应 session → 加密发送）
    workers_.emplace_back([this]{ tun_read_loop(); });

    // io_context 线程
    unsigned hw = std::max(2u, std::thread::hardware_concurrency());
    for (unsigned i = 0; i < hw; ++i)
        workers_.emplace_back([this]{ io_ctx_.run(); });

    for (auto& t : workers_)
        if (t.joinable()) t.join();
}

void Server::stop() {
    running_ = false;
    io_ctx_.stop();
    if (tun_) tun_->close();
}

// ── Accept 循环 ───────────────────────────────────────────────────────────
void Server::start_accept() {
    auto sock = std::make_shared<asio::ip::tcp::socket>(io_ctx_);
    acceptor_.async_accept(*sock, [this, sock](const asio::error_code& ec) {
        if (!ec) {
            VPN_INFO("New connection from {}",
                     sock->remote_endpoint().address().to_string());
            std::thread([this, sock]{ handle_client(sock); }).detach();
        }
        if (running_) start_accept();
    });
}

// ── 握手处理 ──────────────────────────────────────────────────────────────
void Server::handle_client(std::shared_ptr<asio::ip::tcp::socket> sock) {
    handle_handshake(sock);
}

void Server::handle_handshake(std::shared_ptr<asio::ip::tcp::socket> sock) {
    // 读取握手 Init 包
    std::vector<uint8_t> buf(sizeof(HandshakeInit));
    asio::error_code ec;
    size_t n = asio::read(*sock, asio::buffer(buf), ec);
    if (ec || n != sizeof(HandshakeInit)) {
        VPN_WARN("Handshake read failed");
        return;
    }

    HandshakeInit init{};
    std::memcpy(&init, buf.data(), sizeof(HandshakeInit));

    if (init.header.type != MsgType::HANDSHAKE_INIT) {
        VPN_WARN("Not a HANDSHAKE_INIT packet");
        return;
    }

    // 验证 HMAC（使用 PSK）
    if (!cfg_.psk.empty()) {
        uint8_t expected[32];
        unsigned int hlen = 32;
        std::vector<uint8_t> payload(init.sender_pubkey,
                                      init.sender_pubkey + 32 + 12);
        HMAC(EVP_sha256(),
             cfg_.psk.data(), static_cast<int>(cfg_.psk.size()),
             payload.data(), payload.size(),
             expected, &hlen);
        if (std::memcmp(expected, init.hmac, 32) != 0) {
            VPN_WARN("Handshake HMAC verification failed");
            return;
        }
    }

    // 创建 crypto 并完成握手
    auto crypto = make_crypto();
    std::vector<uint8_t> my_pubkey;
    if (!crypto->handshake(init.sender_pubkey, 32, init.nonce, 12, my_pubkey)) {
        VPN_ERROR("Crypto handshake failed");
        return;
    }

    // 创建会话
    auto obfuscators = TunnelManager::build_obfuscators(cfg_.obfuscate_chain);
    uint32_t sid = tunnel_mgr_.create_session(std::move(crypto), std::move(obfuscators));
    Session* sess = tunnel_mgr_.get_session(sid);
    sess->established = true;

    // 构造 HandshakeResp
    HandshakeResp resp{};
    resp.header.type = MsgType::HANDSHAKE_RESP;
    resp.session_id  = sid;
    std::memcpy(resp.sender_pubkey, my_pubkey.data(), 32);
    RAND_bytes(resp.nonce, 12);

    // HMAC over (session_id + pubkey + nonce)
    if (!cfg_.psk.empty()) {
        std::vector<uint8_t> payload(4 + 32 + 12);
        std::memcpy(payload.data(), &sid, 4);
        std::memcpy(payload.data() + 4, my_pubkey.data(), 32);
        std::memcpy(payload.data() + 36, resp.nonce, 12);
        unsigned int hlen = 32;
        HMAC(EVP_sha256(),
             cfg_.psk.data(), static_cast<int>(cfg_.psk.size()),
             payload.data(), payload.size(),
             resp.hmac, &hlen);
    }

    auto resp_buf = serialize_handshake_resp(resp);
    asio::write(*sock, asio::buffer(resp_buf), ec);
    if (ec) { VPN_ERROR("Handshake resp send failed"); return; }

    VPN_INFO("Handshake complete, session_id={}", sid);
    run_session(sock, sid);
}

// ── 会话数据收发 ──────────────────────────────────────────────────────────
void Server::run_session(std::shared_ptr<asio::ip::tcp::socket> sock, uint32_t session_id) {
    // 持续从 TCP 接收数据包 → 解密 → 写入 TUN
    std::vector<uint8_t> len_buf(4);
    while (running_) {
        asio::error_code ec;
        // 先读 4 字节包长度
        asio::read(*sock, asio::buffer(len_buf), ec);
        if (ec) break;

        uint32_t pkt_len =
            static_cast<uint32_t>(len_buf[0]) |
            (static_cast<uint32_t>(len_buf[1]) << 8) |
            (static_cast<uint32_t>(len_buf[2]) << 16) |
            (static_cast<uint32_t>(len_buf[3]) << 24);

        if (pkt_len == 0 || pkt_len > 65536) break;

        std::vector<uint8_t> pkt(pkt_len);
        asio::read(*sock, asio::buffer(pkt), ec);
        if (ec) break;

        Session* sess = tunnel_mgr_.get_session(session_id);
        if (!sess) break;

        auto plain = sess->unpack_and_decrypt(pkt.data(), pkt.size());
        if (!plain.empty())
            tun_->write(plain.data(), plain.size());
    }

    tunnel_mgr_.remove_session(session_id);
    VPN_INFO("Session {} ended", session_id);
}

// ── TUN 读取循环（发送方向）──────────────────────────────────────────────
void Server::tun_read_loop() {
    std::vector<uint8_t> buf(65536);
    while (running_) {
        ssize_t n = tun_->read(buf.data(), buf.size());
        if (n <= 0) continue;

        // 简单广播给所有 session（生产环境应按 IP 路由）
        // 这里仅演示：发给第一个已建立的会话
        // TODO: 实际部署需要路由表
        (void)n; // suppress unused warning in demo
    }
}

// ── Crypto 工厂 ───────────────────────────────────────────────────────────
std::unique_ptr<ICrypto> Server::make_crypto() const {
    if (cfg_.cipher == CipherType::AES_256_GCM)
        return std::make_unique<AesGcmCrypto>();
    return std::make_unique<ChaCha20Crypto>();
}

} // namespace vpn
