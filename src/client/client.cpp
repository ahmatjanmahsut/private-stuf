#include "client.hpp"
#include "common/logger.hpp"
#include "common/packet.hpp"
#include "crypto/chacha20_crypto.hpp"
#include "crypto/aes_gcm_crypto.hpp"
#ifndef _WIN32
#  include "tun/linux_tun.hpp"
#else
#  include "tun/windows_tun.hpp"
#endif
#include <openssl/rand.h>
#include <openssl/hmac.h>
#include <cstring>
#include <stdexcept>
#include <thread>
#include <chrono>

namespace vpn {

// ── 构造 ──────────────────────────────────────────────────────────────────
Client::Client(const Config& cfg)
    : cfg_(cfg), io_ctx_(), tunnel_mgr_(cfg)
{
#ifndef _WIN32
    tun_ = std::make_unique<LinuxTun>();
#else
    tun_ = std::make_unique<WindowsTun>();
#endif
    if (!tun_->open(cfg_.tun.name, cfg_.tun.address, cfg_.tun.netmask, cfg_.tun.mtu)) {
        throw std::runtime_error("Failed to open TUN device");
    }
    VPN_INFO("Client TUN: {} addr={}", cfg_.tun.name, cfg_.tun.address);
}

Client::~Client() { stop(); }

void Client::stop() {
    running_ = false;
    io_ctx_.stop();
    if (tun_) tun_->close();
}

// ── 运行 ──────────────────────────────────────────────────────────────────
void Client::run() {
    running_ = true;

    int retries = 0;
    while (running_) {
        if (connect_and_handshake()) break;
        retries++;
        VPN_WARN("Handshake failed, retry {}/5 in 3s...", retries);
        std::this_thread::sleep_for(std::chrono::seconds(3));
        if (retries >= 5) {
            VPN_ERROR("Cannot connect to server, aborting.");
            return;
        }
    }

    std::thread recv_thread([this]{ recv_loop(); });
    std::thread tun_thread([this]{ tun_read_loop(); });

    recv_thread.join();
    tun_thread.join();
}

// ── 连接 + 握手（两步 ECDH：先取公钥发出，再用对端公钥做 ECDH）──────────
bool Client::connect_and_handshake() {
    sock_ = std::make_shared<asio::ip::tcp::socket>(io_ctx_);

    asio::ip::tcp::resolver resolver(io_ctx_);
    auto endpoints = resolver.resolve(cfg_.peer_host, std::to_string(cfg_.peer_port));

    asio::error_code ec;
    asio::connect(*sock_, endpoints, ec);
    if (ec) {
        VPN_ERROR("Connect to {}:{} failed: {}", cfg_.peer_host, cfg_.peer_port, ec.message());
        return false;
    }
    VPN_INFO("Connected to {}:{}", cfg_.peer_host, cfg_.peer_port);

    // 创建 crypto，生成密钥对
    auto crypto = make_crypto();
    uint8_t nonce[12];
    RAND_bytes(nonce, 12);

    // 步骤1：仅取本端公钥，不做 ECDH
    std::vector<uint8_t> my_pubkey;
    if (!crypto->get_public_key(my_pubkey)) {
        VPN_ERROR("get_public_key failed");
        return false;
    }

    // 构造 HandshakeInit
    HandshakeInit init{};
    init.header.type = MsgType::HANDSHAKE_INIT;
    std::memcpy(init.sender_pubkey, my_pubkey.data(), 32);
    std::memcpy(init.nonce, nonce, 12);

    // HMAC-SHA256(pubkey || nonce) with PSK
    if (!cfg_.psk.empty()) {
        std::vector<uint8_t> payload(my_pubkey.begin(), my_pubkey.end());
        payload.insert(payload.end(), nonce, nonce + 12);
        unsigned int hlen = 32;
        HMAC(EVP_sha256(),
             cfg_.psk.data(), static_cast<int>(cfg_.psk.size()),
             payload.data(), payload.size(),
             init.hmac, &hlen);
    }

    auto init_buf = serialize_handshake_init(init);
    asio::write(*sock_, asio::buffer(init_buf), ec);
    if (ec) { VPN_ERROR("Handshake init send failed"); return false; }

    // 读取 HandshakeResp
    std::vector<uint8_t> resp_buf(sizeof(HandshakeResp));
    asio::read(*sock_, asio::buffer(resp_buf), ec);
    if (ec) { VPN_ERROR("Handshake resp read failed"); return false; }

    HandshakeResp resp{};
    std::memcpy(&resp, resp_buf.data(), sizeof(HandshakeResp));
    if (resp.header.type != MsgType::HANDSHAKE_RESP) {
        VPN_ERROR("Expected HANDSHAKE_RESP");
        return false;
    }

    // 验证服务端 HMAC
    if (!cfg_.psk.empty()) {
        uint8_t expected[32];
        unsigned int hlen = 32;
        std::vector<uint8_t> payload(4 + 32 + 12);
        std::memcpy(payload.data(),      &resp.session_id,   4);
        std::memcpy(payload.data() + 4,   resp.sender_pubkey, 32);
        std::memcpy(payload.data() + 36,  resp.nonce,         12);
        HMAC(EVP_sha256(),
             cfg_.psk.data(), static_cast<int>(cfg_.psk.size()),
             payload.data(), payload.size(),
             expected, &hlen);
        if (std::memcmp(expected, resp.hmac, 32) != 0) {
            VPN_ERROR("Server HMAC verification failed");
            return false;
        }
    }

    // 步骤2：用服务端真实公钥完成 ECDH + HKDF 推导会话密钥
    if (!crypto->do_ecdh(resp.sender_pubkey, 32, nonce, 12)) {
        VPN_ERROR("ECDH with server pubkey failed");
        return false;
    }

    // 注册会话
    auto obfuscators = TunnelManager::build_obfuscators(cfg_.obfuscate_chain);
    session_id_ = tunnel_mgr_.create_session(std::move(crypto), std::move(obfuscators));
    Session* sess = tunnel_mgr_.get_session(session_id_);
    sess->session_id  = resp.session_id;  // 使用服务端分配的 ID
    sess->established = true;

    VPN_INFO("Handshake complete, session_id={}", resp.session_id);
    return true;
}

// ── 接收循环（server → client）────────────────────────────────────────────
void Client::recv_loop() {
    std::vector<uint8_t> len_buf(4);
    while (running_) {
        asio::error_code ec;
        asio::read(*sock_, asio::buffer(len_buf), ec);
        if (ec) { VPN_WARN("recv_loop: {}", ec.message()); break; }

        uint32_t pkt_len =
            static_cast<uint32_t>(len_buf[0])        |
            (static_cast<uint32_t>(len_buf[1]) << 8)  |
            (static_cast<uint32_t>(len_buf[2]) << 16) |
            (static_cast<uint32_t>(len_buf[3]) << 24);
        if (pkt_len == 0 || pkt_len > 65536) break;

        std::vector<uint8_t> pkt(pkt_len);
        asio::read(*sock_, asio::buffer(pkt), ec);
        if (ec) break;

        Session* sess = tunnel_mgr_.get_session(session_id_);
        if (!sess) break;

        auto plain = sess->unpack_and_decrypt(pkt.data(), pkt.size());
        if (!plain.empty())
            tun_->write(plain.data(), plain.size());
    }
    VPN_INFO("Client recv_loop ended");
    running_ = false;
}

// ── TUN 读取循环（client → server）───────────────────────────────────────
void Client::tun_read_loop() {
    std::vector<uint8_t> buf(65536);
    while (running_) {
        ssize_t n = tun_->read(buf.data(), buf.size());
        if (n <= 0) continue;

        Session* sess = tunnel_mgr_.get_session(session_id_);
        if (!sess || !sess->established) continue;

        auto encrypted = sess->encrypt_and_pack(buf.data(), static_cast<size_t>(n));
        if (encrypted.empty()) continue;

        uint32_t len = static_cast<uint32_t>(encrypted.size());
        uint8_t len_hdr[4] = {
            static_cast<uint8_t>(len        & 0xff),
            static_cast<uint8_t>((len >>  8) & 0xff),
            static_cast<uint8_t>((len >> 16) & 0xff),
            static_cast<uint8_t>((len >> 24) & 0xff)
        };

        asio::error_code ec;
        asio::write(*sock_, asio::buffer(len_hdr, 4), ec);
        if (ec) { running_ = false; break; }
        asio::write(*sock_, asio::buffer(encrypted), ec);
        if (ec) { running_ = false; break; }
    }
    VPN_INFO("Client tun_read_loop ended");
}

std::unique_ptr<ICrypto> Client::make_crypto() const {
    if (cfg_.cipher == CipherType::AES_256_GCM)
        return std::make_unique<AesGcmCrypto>();
    return std::make_unique<ChaCha20Crypto>();
}

} // namespace vpn
