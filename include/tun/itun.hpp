#pragma once
#include <cstddef>
#include <cstdint>
#include <string>

#ifdef _WIN32
  using ssize_t = long long;
#endif

namespace vpn {

class ITunDevice {
public:
    virtual ~ITunDevice() = default;

    virtual bool open(const std::string& name,
                      const std::string& address,
                      const std::string& netmask,
                      int mtu = 1420) = 0;

    virtual ssize_t read(uint8_t* buf, size_t len) = 0;
    virtual ssize_t write(const uint8_t* buf, size_t len) = 0;
    virtual void    close() = 0;
    virtual bool    is_open() const = 0;
    virtual const std::string& dev_name() const = 0;
};

} // namespace vpn
