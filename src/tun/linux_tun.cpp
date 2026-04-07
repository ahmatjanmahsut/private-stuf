#include "tun/linux_tun.hpp"
#ifndef _WIN32

#include "common/logger.hpp"
#include <linux/if_tun.h>
#include <net/if.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <fcntl.h>
#include <unistd.h>
#include <cstring>
#include <cerrno>
#include <stdexcept>

namespace vpn {

bool LinuxTun::open(const std::string& name,
                    const std::string& address,
                    const std::string& netmask,
                    int mtu) {
    fd_ = ::open("/dev/net/tun", O_RDWR);
    if (fd_ < 0) {
        VPN_ERROR("Cannot open /dev/net/tun: {}", strerror(errno));
        return false;
    }

    struct ifreq ifr{};
    ifr.ifr_flags = IFF_TUN | IFF_NO_PI;
    if (!name.empty())
        strncpy(ifr.ifr_name, name.c_str(), IFNAMSIZ - 1);

    if (ioctl(fd_, TUNSETIFF, &ifr) < 0) {
        VPN_ERROR("TUNSETIFF failed: {}", strerror(errno));
        ::close(fd_);
        fd_ = -1;
        return false;
    }
    name_ = ifr.ifr_name;
    VPN_INFO("TUN device {} created", name_);

    if (!set_address(address, netmask)) { close(); return false; }
    if (!set_mtu(mtu))                  { close(); return false; }
    if (!set_up())                      { close(); return false; }

    return true;
}

bool LinuxTun::set_address(const std::string& address, const std::string& netmask) {
    int sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (sock < 0) return false;

    struct ifreq ifr{};
    strncpy(ifr.ifr_name, name_.c_str(), IFNAMSIZ - 1);

    auto set_inet = [&](int cmd, const std::string& ip) -> bool {
        auto* sin = reinterpret_cast<struct sockaddr_in*>(&ifr.ifr_addr);
        sin->sin_family = AF_INET;
        if (inet_pton(AF_INET, ip.c_str(), &sin->sin_addr) != 1) return false;
        return ioctl(sock, cmd, &ifr) >= 0;
    };

    bool ok = set_inet(SIOCSIFADDR, address) && set_inet(SIOCSIFNETMASK, netmask);
    ::close(sock);
    if (!ok) VPN_ERROR("Failed to set TUN address/netmask");
    return ok;
}

bool LinuxTun::set_mtu(int mtu) {
    int sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (sock < 0) return false;
    struct ifreq ifr{};
    strncpy(ifr.ifr_name, name_.c_str(), IFNAMSIZ - 1);
    ifr.ifr_mtu = mtu;
    bool ok = ioctl(sock, SIOCSIFMTU, &ifr) >= 0;
    ::close(sock);
    return ok;
}

bool LinuxTun::set_up() {
    int sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (sock < 0) return false;
    struct ifreq ifr{};
    strncpy(ifr.ifr_name, name_.c_str(), IFNAMSIZ - 1);
    ioctl(sock, SIOCGIFFLAGS, &ifr);
    ifr.ifr_flags |= IFF_UP | IFF_RUNNING;
    bool ok = ioctl(sock, SIOCSIFFLAGS, &ifr) >= 0;
    ::close(sock);
    if (ok) VPN_INFO("TUN device {} is UP", name_);
    return ok;
}

ssize_t LinuxTun::read(uint8_t* buf, size_t len) {
    return ::read(fd_, buf, len);
}

ssize_t LinuxTun::write(const uint8_t* buf, size_t len) {
    return ::write(fd_, buf, len);
}

void LinuxTun::close() {
    if (fd_ >= 0) {
        ::close(fd_);
        fd_ = -1;
        VPN_INFO("TUN device {} closed", name_);
    }
}

} // namespace vpn
#endif // !_WIN32
