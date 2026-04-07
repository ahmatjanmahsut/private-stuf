#include "common/config.hpp"
#include <yaml-cpp/yaml.h>
#include <stdexcept>

namespace vpn {

static CipherType parse_cipher(const std::string& s) {
    if (s == "aes-256-gcm" || s == "AES-256-GCM")
        return CipherType::AES_256_GCM;
    return CipherType::CHACHA20_POLY1305;
}

static ObfuscateMode parse_obf(const std::string& s) {
    if (s == "http"      || s == "HTTP")      return ObfuscateMode::HTTP;
    if (s == "websocket" || s == "WebSocket") return ObfuscateMode::WEBSOCKET;
    if (s == "padding"   || s == "Padding")   return ObfuscateMode::PADDING;
    return ObfuscateMode::NONE;
}

Config Config::load_from_file(const std::string& path) {
    YAML::Node node = YAML::LoadFile(path);
    Config cfg;

    if (node["role"])
        cfg.is_server = (node["role"].as<std::string>() == "server");

    if (node["listen"]) {
        auto& l = node["listen"];
        if (l["host"]) cfg.listen_host = l["host"].as<std::string>();
        if (l["port"]) cfg.listen_port = l["port"].as<uint16_t>();
    }

    if (node["peer"]) {
        auto& p = node["peer"];
        if (p["host"]) cfg.peer_host = p["host"].as<std::string>();
        if (p["port"]) cfg.peer_port = p["port"].as<uint16_t>();
    }

    if (node["cipher"])
        cfg.cipher = parse_cipher(node["cipher"].as<std::string>());

    if (node["psk"])
        cfg.psk = node["psk"].as<std::string>();

    if (node["obfuscate_chain"]) {
        for (const auto& item : node["obfuscate_chain"])
            cfg.obfuscate_chain.push_back(parse_obf(item.as<std::string>()));
    }

    if (node["tun"]) {
        auto& t = node["tun"];
        if (t["name"])    cfg.tun.name    = t["name"].as<std::string>();
        if (t["address"]) cfg.tun.address = t["address"].as<std::string>();
        if (t["netmask"]) cfg.tun.netmask = t["netmask"].as<std::string>();
        if (t["mtu"])     cfg.tun.mtu     = t["mtu"].as<int>();
    }

    if (node["log_level"])          cfg.log_level          = node["log_level"].as<int>();
    if (node["handshake_timeout"])  cfg.handshake_timeout  = node["handshake_timeout"].as<int>();
    if (node["keepalive_interval"]) cfg.keepalive_interval = node["keepalive_interval"].as<int>();

    return cfg;
}

Config Config::load_server_defaults() {
    Config cfg;
    cfg.is_server   = true;
    cfg.listen_port = 51820;
    cfg.tun.address = "10.0.0.1";
    cfg.obfuscate_chain = { ObfuscateMode::PADDING, ObfuscateMode::WEBSOCKET };
    return cfg;
}

Config Config::load_client_defaults() {
    Config cfg;
    cfg.is_server   = false;
    cfg.listen_port = 0;
    cfg.tun.address = "10.0.0.2";
    cfg.obfuscate_chain = { ObfuscateMode::PADDING, ObfuscateMode::WEBSOCKET };
    return cfg;
}

} // namespace vpn
