#pragma once
#ifndef _WIN32

#include "itun.hpp"

namespace vpn {

class LinuxTun : public ITunDevice {
public:
    LinuxTun()  = default;
    ~LinuxTun() override { close(); }

    bool open(const std::string& name,
              const std::string& address,
              const std::string& netmask,
              int mtu = 1420) override;

    ssize_t read(uint8_t* buf, size_t len) override;
    ssize_t write(const uint8_t* buf, size_t len) override;
    void    close() override;
    bool    is_open() const override { return fd_ >= 0; }
    const std::string& dev_name() const override { return name_; }

private:
    int         fd_   = -1;
    std::string name_;

    bool set_address(const std::string& address, const std::string& netmask);
    bool set_mtu(int mtu);
    bool set_up();
};

} // namespace vpn

#endif // !_WIN32
