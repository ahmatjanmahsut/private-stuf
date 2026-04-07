#include "common/config.hpp"
#include <yaml-cpp/yaml.h>
#include <fstream>
#include <stdexcept>

namespace vpn {

static CipherType parse_cipher(const std::string& s) {
    if (s == "aes-256-gcm" || s == "AES-256-GCM") {
        return CipherType::AES_256_GCM;
    }
    return CipherType::CHACHA20_POLY1305;
}

static ObfuscateMode parse_obf(const std::string& s) {
    if (s == "http" || s == "HTTP") {
        return ObfuscateMode::HTTP;
    }
    if (s == "websocket" || s == "WebSocket" || s == "WEBSOCKET") {
        return ObfuscateMode::WEBSOCKET;
    }
    if (s == "padding" || s == "Padding" || s == "PADDING") {
        return ObfuscateMode::PADDING;
    }
    return ObfuscateMode::NONE;
}

std::string to_string(CipherType cipher) {
    switch (cipher) {
        case CipherType::AES_256_GCM:
            return "aes-256-gcm";
        case CipherType::CHACHA20_POLY1305:
        default:
            return "chacha20-poly1305";
    }
}

std::string to_string(ObfuscateMode mode) {
    switch (mode) {
        case ObfuscateMode::HTTP:
            return "http";
        case ObfuscateMode::WEBSOCKET:
            return "websocket";
        case ObfuscateMode::PADDING:
            return "padding";
        case ObfuscateMode::NONE:
        default:
            return "none";
    }
}

static Config parse_config_node(const YAML::Node& node) {
    Config cfg;

    if (node["role"]) {
        cfg.is_server = (node["role"].as<std::string>() == "server");
    }

    if (node["listen"]) {
        const auto& l = node["listen"];
        if (l["host"]) cfg.listen_host = l["host"].as<std::string>();
        if (l["port"]) cfg.listen_port = l["port"].as<uint16_t>();
    }

    if (node["peer"]) {
        const auto& p = node["peer"];
        if (p["host"]) cfg.peer_host = p["host"].as<std::string>();
        if (p["port"]) cfg.peer_port = p["port"].as<uint16_t>();
    }

    if (node["cipher"]) {
        cfg.cipher = parse_cipher(node["cipher"].as<std::string>());
    }

    if (node["psk"]) {
        cfg.psk = node["psk"].as<std::string>();
    }

    if (node["obfuscate_chain"]) {
        for (const auto& item : node["obfuscate_chain"]) {
            const auto mode = parse_obf(item.as<std::string>());
            if (mode != ObfuscateMode::NONE) {
                cfg.obfuscate_chain.push_back(mode);
            }
        }
    }

    if (node["tun"]) {
        const auto& t = node["tun"];
        if (t["name"]) cfg.tun.name = t["name"].as<std::string>();
        if (t["address"]) cfg.tun.address = t["address"].as<std::string>();
        if (t["netmask"]) cfg.tun.netmask = t["netmask"].as<std::string>();
        if (t["mtu"]) cfg.tun.mtu = t["mtu"].as<int>();
    }

    if (node["web_ui"]) {
        const auto& w = node["web_ui"];
        if (w["enabled"]) cfg.web_ui.enabled = w["enabled"].as<bool>();
        if (w["host"]) cfg.web_ui.host = w["host"].as<std::string>();
        if (w["port"]) cfg.web_ui.port = w["port"].as<uint16_t>();
        if (w["auto_start_tunnel"]) {
            cfg.web_ui.auto_start_tunnel = w["auto_start_tunnel"].as<bool>();
        }
    }

    if (node["log_level"]) cfg.log_level = node["log_level"].as<int>();
    if (node["handshake_timeout"]) cfg.handshake_timeout = node["handshake_timeout"].as<int>();
    if (node["keepalive_interval"]) cfg.keepalive_interval = node["keepalive_interval"].as<int>();

    return cfg;
}

Config Config::load_from_file(const std::string& path) {
    return parse_config_node(YAML::LoadFile(path));
}

Config Config::load_from_yaml_string(const std::string& yaml_text) {
    return parse_config_node(YAML::Load(yaml_text));
}

Config Config::load_server_defaults() {
    Config cfg;
    cfg.is_server = true;
    cfg.listen_port = 51820;
    cfg.tun.address = "10.0.0.1";
    cfg.obfuscate_chain = {ObfuscateMode::PADDING, ObfuscateMode::WEBSOCKET};
    cfg.web_ui.enabled = false;
    cfg.web_ui.host = "127.0.0.1";
    cfg.web_ui.port = 8080;
    cfg.web_ui.auto_start_tunnel = false;
    return cfg;
}

Config Config::load_client_defaults() {
    Config cfg;
    cfg.is_server = false;
    cfg.listen_port = 0;
    cfg.tun.address = "10.0.0.2";
    cfg.obfuscate_chain = {ObfuscateMode::PADDING, ObfuscateMode::WEBSOCKET};
    cfg.web_ui.enabled = false;
    cfg.web_ui.host = "127.0.0.1";
    cfg.web_ui.port = 8081;
    cfg.web_ui.auto_start_tunnel = false;
    return cfg;
}

std::string Config::to_yaml_string() const {
    YAML::Emitter out;
    out << YAML::BeginMap;

    out << YAML::Key << "role" << YAML::Value << (is_server ? "server" : "client");

    if (is_server) {
        out << YAML::Key << "listen" << YAML::Value << YAML::BeginMap;
        out << YAML::Key << "host" << YAML::Value << listen_host;
        out << YAML::Key << "port" << YAML::Value << listen_port;
        out << YAML::EndMap;
    }

    if (!is_server) {
        out << YAML::Key << "peer" << YAML::Value << YAML::BeginMap;
        out << YAML::Key << "host" << YAML::Value << peer_host;
        out << YAML::Key << "port" << YAML::Value << peer_port;
        out << YAML::EndMap;
    }


    out << YAML::Key << "cipher" << YAML::Value << vpn::to_string(cipher);
    out << YAML::Key << "psk" << YAML::Value << psk;

    out << YAML::Key << "obfuscate_chain" << YAML::Value << YAML::BeginSeq;
    for (const auto mode : obfuscate_chain) {
        if (mode != ObfuscateMode::NONE) {
            out << vpn::to_string(mode);
        }
    }
    out << YAML::EndSeq;

    out << YAML::Key << "tun" << YAML::Value << YAML::BeginMap;
    out << YAML::Key << "name" << YAML::Value << tun.name;
    out << YAML::Key << "address" << YAML::Value << tun.address;
    out << YAML::Key << "netmask" << YAML::Value << tun.netmask;
    out << YAML::Key << "mtu" << YAML::Value << tun.mtu;
    out << YAML::EndMap;

    out << YAML::Key << "web_ui" << YAML::Value << YAML::BeginMap;
    out << YAML::Key << "enabled" << YAML::Value << web_ui.enabled;
    out << YAML::Key << "host" << YAML::Value << web_ui.host;
    out << YAML::Key << "port" << YAML::Value << web_ui.port;
    out << YAML::Key << "auto_start_tunnel" << YAML::Value << web_ui.auto_start_tunnel;
    out << YAML::EndMap;

    out << YAML::Key << "log_level" << YAML::Value << log_level;
    out << YAML::Key << "handshake_timeout" << YAML::Value << handshake_timeout;
    out << YAML::Key << "keepalive_interval" << YAML::Value << keepalive_interval;

    out << YAML::EndMap;
    return out.c_str();
}

void Config::save_to_file(const std::string& path) const {
    std::ofstream ofs(path, std::ios::binary | std::ios::trunc);
    if (!ofs) {
        throw std::runtime_error("Cannot open config file for write: " + path);
    }
    ofs << to_yaml_string();
    ofs << '\n';
}

} // namespace vpn
