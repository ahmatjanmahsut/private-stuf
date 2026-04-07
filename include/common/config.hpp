#pragma once
#include <cstdint>
#include <string>
#include <vector>

namespace vpn {

enum class CipherType {
    CHACHA20_POLY1305,
    AES_256_GCM
};

enum class ObfuscateMode {
    NONE,
    HTTP,
    WEBSOCKET,
    PADDING
};

struct TunConfig {
    std::string name    = "tun0";
    std::string address = "10.0.0.1";
    std::string netmask = "255.255.255.0";
    int         mtu     = 1420;
};

struct WebUiConfig {
    bool        enabled           = false;
    std::string host              = "127.0.0.1";
    uint16_t    port              = 8080;
    bool        auto_start_tunnel = false;
};

struct Config {
    // role
    bool is_server = false;

    // network
    std::string listen_host = "0.0.0.0";
    uint16_t    listen_port = 51820;
    std::string peer_host;
    uint16_t    peer_port   = 51820;

    // crypto
    CipherType cipher = CipherType::CHACHA20_POLY1305;
    std::string psk;

    // obfuscation chain (applied in order on send, reversed on recv)
    std::vector<ObfuscateMode> obfuscate_chain;

    // TUN
    TunConfig tun;

    // Web UI
    WebUiConfig web_ui;

    // misc
    int log_level          = 1;
    int handshake_timeout  = 5;
    int keepalive_interval = 25;

    static Config load_from_file(const std::string& path);
    static Config load_from_yaml_string(const std::string& yaml_text);
    static Config load_server_defaults();
    static Config load_client_defaults();

    void        save_to_file(const std::string& path) const;
    std::string to_yaml_string() const;
};

std::string to_string(CipherType cipher);
std::string to_string(ObfuscateMode mode);

} // namespace vpn
