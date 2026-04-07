#include "common/logger.hpp"
#include <spdlog/sinks/stdout_color_sinks.h>

namespace vpn {

std::shared_ptr<spdlog::logger> Logger::instance_;

static spdlog::level::level_enum map_level(int level) {
    switch (level) {
        case 0: return spdlog::level::trace;
        case 1: return spdlog::level::info;
        case 2: return spdlog::level::warn;
        case 3: return spdlog::level::err;
        default: return spdlog::level::info;
    }
}

void Logger::init(const std::string& name, int level) {
    if (!instance_) {
        instance_ = spdlog::stdout_color_mt(name);
    }
    instance_->set_level(map_level(level));
    instance_->set_pattern("[%Y-%m-%d %H:%M:%S.%e] [%^%l%$] [%t] %v");
    spdlog::set_default_logger(instance_);
    spdlog::set_level(map_level(level));
}

void Logger::set_level(int level) {
    get()->set_level(map_level(level));
    spdlog::set_level(map_level(level));
}

std::shared_ptr<spdlog::logger> Logger::get() {
    if (!instance_) {
        init();
    }
    return instance_;
}

} // namespace vpn
