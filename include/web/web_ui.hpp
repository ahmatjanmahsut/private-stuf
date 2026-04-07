#pragma once
#include <cstdint>
#include <memory>
#include <string>

namespace vpn {

struct WebUiOptions {
    std::string config_path;
    std::string host_override;
    uint16_t    port_override           = 0;
    bool        has_auto_start_override = false;
    bool        auto_start_override     = false;
};

class WebUiApp {
public:
    explicit WebUiApp(WebUiOptions options);
    ~WebUiApp();

    void run();
    void stop();

private:
    class Impl;
    std::unique_ptr<Impl> impl_;
};

} // namespace vpn
