#include "server/server.hpp"
#include "web/web_ui.hpp"
#include "common/logger.hpp"
#include <csignal>
#include <iostream>
#include <string>

namespace {

struct CliOptions {
    std::string config_path = "config/server.yaml";
    bool show_help = false;
    bool force_web_ui = false;
    bool disable_web_ui = false;
    std::string web_ui_host;
    uint16_t web_ui_port = 0;
    bool has_auto_start_override = false;
    bool auto_start_override = false;
};

vpn::Server* g_server = nullptr;
vpn::WebUiApp* g_web_ui = nullptr;

void signal_handler(int /*sig*/) {
    if (g_web_ui) g_web_ui->stop();
    if (g_server) g_server->stop();
}

void print_usage() {
    std::cout
        << "Usage: vpn_server [config_path] [--config <path>] [--web-ui] [--no-web-ui]\\n"
        << "                  [--web-ui-host <host>] [--web-ui-port <port>] [--web-ui-auto-start]\\n";
}

CliOptions parse_args(int argc, char* argv[]) {
    CliOptions options;
    for (int i = 1; i < argc; ++i) {
        const std::string arg = argv[i];
        if (arg == "-h" || arg == "--help") {
            options.show_help = true;
        } else if (arg == "--config" && i + 1 < argc) {
            options.config_path = argv[++i];
        } else if (arg == "--web-ui") {
            options.force_web_ui = true;
        } else if (arg == "--no-web-ui") {
            options.disable_web_ui = true;
        } else if (arg == "--web-ui-host" && i + 1 < argc) {
            options.web_ui_host = argv[++i];
        } else if (arg == "--web-ui-port" && i + 1 < argc) {
            options.web_ui_port = static_cast<uint16_t>(std::stoi(argv[++i]));
        } else if (arg == "--web-ui-auto-start" || arg == "--start-now") {
            options.has_auto_start_override = true;
            options.auto_start_override = true;
        } else if (!arg.empty() && arg[0] != '-') {
            options.config_path = arg;
        }
    }
    return options;
}

} // namespace

int main(int argc, char* argv[]) {
    const auto options = parse_args(argc, argv);
    if (options.show_help) {
        print_usage();
        return 0;
    }

    vpn::Config cfg;
    bool config_loaded = true;
    std::string load_error;
    try {
        cfg = vpn::Config::load_from_file(options.config_path);
    } catch (const std::exception& e) {
        config_loaded = false;
        load_error = e.what();
        cfg = vpn::Config::load_server_defaults();
    }
    cfg.is_server = true;

    vpn::Logger::init("vpn-server", cfg.log_level);
    VPN_INFO("VPN Server starting, config: {}", options.config_path);
    if (!config_loaded) {
        VPN_WARN("Cannot load config '{}': {}. Using defaults.", options.config_path, load_error);
    }

    std::signal(SIGINT, signal_handler);
    std::signal(SIGTERM, signal_handler);

    const bool use_web_ui = !options.disable_web_ui && (options.force_web_ui || cfg.web_ui.enabled);

    try {
        if (use_web_ui) {
            vpn::WebUiOptions web_options;
            web_options.config_path = options.config_path;
            web_options.host_override = options.web_ui_host;
            web_options.port_override = options.web_ui_port;
            web_options.has_auto_start_override = options.has_auto_start_override;
            web_options.auto_start_override = options.auto_start_override;

            vpn::WebUiApp app(web_options);
            g_web_ui = &app;
            app.run();
            g_web_ui = nullptr;
        } else {
            vpn::Server server(cfg);
            g_server = &server;
            server.run();
            g_server = nullptr;
        }
    } catch (const std::exception& e) {
        VPN_ERROR("Server fatal error: {}", e.what());
        return 1;
    }

    VPN_INFO("Server stopped.");
    return 0;
}
