#include "client/client.hpp"
#include "common/logger.hpp"
#include <csignal>
#include <iostream>

static vpn::Client* g_client = nullptr;

static void signal_handler(int /*sig*/) {
    if (g_client) g_client->stop();
}

int main(int argc, char* argv[]) {
    std::string config_path = "config/client.yaml";
    if (argc >= 2) config_path = argv[1];

    vpn::Logger::init("vpn-client", 1);
    VPN_INFO("VPN Client starting, config: {}", config_path);

    vpn::Config cfg;
    try {
        cfg = vpn::Config::load_from_file(config_path);
    } catch (const std::exception& e) {
        VPN_WARN("Cannot load config '{}': {}. Using defaults.", config_path, e.what());
        cfg = vpn::Config::load_client_defaults();
    }
    cfg.is_server = false;

    std::signal(SIGINT,  signal_handler);
#ifndef _WIN32
    std::signal(SIGTERM, signal_handler);
#endif

    try {
        vpn::Client client(cfg);
        g_client = &client;
        client.run();
    } catch (const std::exception& e) {
        VPN_ERROR("Client fatal error: {}", e.what());
        return 1;
    }

    VPN_INFO("Client stopped.");
    return 0;
}
