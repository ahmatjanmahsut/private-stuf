#pragma once
#include <memory>
#include <string>
#include <spdlog/spdlog.h>
#include <spdlog/sinks/stdout_color_sinks.h>

namespace vpn {

class Logger {
public:
    static void init(const std::string& name = "vpntunnel", int level = 1);
    static void set_level(int level);
    static std::shared_ptr<spdlog::logger> get();

private:
    static std::shared_ptr<spdlog::logger> instance_;
};

#define VPN_TRACE(...)  vpn::Logger::get()->trace(__VA_ARGS__)
#define VPN_INFO(...)   vpn::Logger::get()->info(__VA_ARGS__)
#define VPN_WARN(...)   vpn::Logger::get()->warn(__VA_ARGS__)
#define VPN_ERROR(...)  vpn::Logger::get()->error(__VA_ARGS__)
#define VPN_CRITICAL(...) vpn::Logger::get()->critical(__VA_ARGS__)

} // namespace vpn
