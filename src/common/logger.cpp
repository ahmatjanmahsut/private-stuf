#include "common/logger.hpp"
#include <spdlog/sinks/stdout_color_sinks.h>

namespace vpn {

std::shared_ptr<spdlog::logger> Logger::instance_;

void Logger::init(const std::string& name, int level) {
    instance_ = spdlog::stdout_color_mt(name);
    switch (level) {
        case 0:  instance_->set_level(spdlog::level::trace); break;
        case 1:  instance_->set_level(spdlog::level::info);  break;
        case 2:  instance_->set_level(spdlog::level::warn);  break;
        case 3:  instance_->set_level(spdlog::level::err);   break;
        default: instance_->set_level(spdlog::level::info);  break;
    }
    instance_->set_pattern("[%Y-%m-%d %H:%M:%S.%e] [%^%l%$] [%t] %v");
    spdlog::set_default_logger(instance_);
}

std::shared_ptr<spdlog::logger> Logger::get() {
    if (!instance_) {
        init();
    }
    return instance_;
}

} // namespace vpn
