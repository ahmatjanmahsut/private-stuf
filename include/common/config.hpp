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
    // pre-shared key (hex string, 32 bytes)
    std::string psk;

    // obfuscation chain (applied in order on send, reversed on recv)
    std::vector<ObfuscateMode> obfuscate_chain;

    // TUN
    TunConfig tun;

    // misc
    int  log_level         = 1;   // 0=trace,1=info,2=warn,3=error
    int  handshake_timeout = 5;   // seconds
    int  keepalive_interval= 25;  // seconds

    static Config load_from_file(const std::string& path);
    static Config load_server_defaults();
    static Config load_client_defaults();
};

} // namespace vpn
