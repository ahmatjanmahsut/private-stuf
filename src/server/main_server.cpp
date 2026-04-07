#include "server/server.hpp"
#include "common/logger.hpp"
#include <csignal>
#include <iostream>

static vpn::Server* g_server = nullptr;

static void signal_handler(int /*sig*/) {
    if (g_server) g_server->stop();
}

int main(int argc, char* argv[]) {
    std::string config_path = "config/server.yaml";
    if (argc >= 2) config_path = argv[1];

    vpn::Logger::init("vpn-server", 1);
    VPN_INFO("VPN Server starting, config: {}", config_path);

    vpn::Config cfg;
    try {
        cfg = vpn::Config::load_from_file(config_path);
    } catch (const std::exception& e) {
        VPN_WARN("Cannot load config '{}': {}. Using defaults.", config_path, e.what());
        cfg = vpn::Config::load_server_defaults();
    }
    cfg.is_server = true;

    std::signal(SIGINT,  signal_handler);
    std::signal(SIGTERM, signal_handler);

    try {
        vpn::Server server(cfg);
        g_server = &server;
        server.run();
    } catch (const std::exception& e) {
        VPN_ERROR("Server fatal error: {}", e.what());
        return 1;
    }

    VPN_INFO("Server stopped.");
    return 0;
}
