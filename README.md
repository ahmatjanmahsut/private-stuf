# VPN Tunnel

[![CI](https://github.com/ahmatjanmahsut/private-stuf/actions/workflows/ci.yml/badge.svg)](https://github.com/ahmatjanmahsut/private-stuf/actions/workflows/ci.yml)
[![Release](https://github.com/ahmatjanmahsut/private-stuf/actions/workflows/release.yml/badge.svg)](https://github.com/ahmatjanmahsut/private-stuf/actions/workflows/release.yml)
[![Latest Release](https://img.shields.io/github/v/release/ahmatjanmahsut/private-stuf?label=latest)](https://github.com/ahmatjanmahsut/private-stuf/releases/latest)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)

一个用 C++17 实现的加密隧道软件，功能对标 WireGuard，并集成类 Clash 的多层流量混淆能力。

---

## 目录

- [功能特性](#功能特性)
- [架构概览](#架构概览)
- [目录结构](#目录结构)
- [依赖要求](#依赖要求)
- [编译构建](#编译构建)
  - [Linux（服务端 + 客户端）](#linux服务端--客户端)
  - [Windows（仅客户端）](#windows仅客户端)
- [Web UI 控制台](#web-ui-控制台)
- [部署教程](#部署教程)
  - [第一步：服务端部署（Linux）](#第一步服务端部署linux)
  - [第二步：客户端部署（Linux）](#第二步客户端部署linux)
  - [第三步：客户端部署（Windows）](#第三步客户端部署windows)
  - [第四步：验证连通性](#第四步验证连通性)
- [配置文件说明](#配置文件说明)
  - [服务端配置](#服务端配置)
  - [客户端配置](#客户端配置)
  - [配置项详解](#配置项详解)
- [混淆模式说明](#混淆模式说明)
- [加密方案说明](#加密方案说明)
- [握手协议流程](#握手协议流程)
- [安全性说明](#安全性说明)
- [常见问题](#常见问题)
- [许可证](#许可证)

---

## 功能特性

| 特性 | 说明 |
|------|------|
| **加密传输** | ChaCha20-Poly1305 / AES-256-GCM，配置文件切换 |
| **密钥交换** | X25519 ECDH 椭圆曲线 Diffie-Hellman |
| **密钥推导** | HKDF-SHA256，每次握手产生唯一会话密钥 |
| **身份认证** | HMAC-SHA256 预共享密钥（PSK）校验握手包 |
| **防重放攻击** | 64-bit 单调递增 nonce 计数器 + 256-bit 滑动窗口 |
| **HTTP 伪装混淆** | 将数据包装为 HTTP POST 请求，绕过 DPI 检测 |
| **WebSocket 混淆** | 按 RFC 6455 封装 WebSocket 二进制帧，含随机 masking |
| **随机 Padding** | 在包尾追加随机填充字节，破坏流量特征 |
| **流量整形** | 发包时随机微秒延迟，对抗时序分析 |
| **混淆链** | 支持多层混淆叠加（如 padding → websocket），可任意组合 |
| **TUN 虚拟网卡** | 服务端 `/dev/net/tun`；Windows 客户端 WinTun |
| **跨平台** | 服务端：Linux；客户端：Linux / Windows |
| **多客户端** | 服务端支持同时接入多个客户端会话 |
| **Web UI 控制台** | 浏览器内完成启动/停止、配置保存、重载、重启与全部核心参数调整 |
| **异步 I/O** | 基于 Asio standalone 实现非阻塞网络通信 |

---

## 架构概览

```
┌─────────────────────────────────────────────────────┐
│                       客户端                         │
│  应用程序  →  TUN 虚拟网卡  →  加密层  →  混淆层  →  TCP │
└──────────────────────────────┬──────────────────────┘
                               │  TCP（51820 端口）
                               ▼
┌─────────────────────────────────────────────────────┐
│                       服务端                         │
│  TCP  →  去混淆层  →  解密层  →  TUN 虚拟网卡  →  路由 │
└─────────────────────────────────────────────────────┘
```

**数据发送流程（客户端 → 服务端）：**

```
原始 IP 数据包
    │
    ▼ Session::encrypt_and_pack()
加密（ChaCha20-Poly1305 / AES-256-GCM）+ DataPacket 封装
    │
    ▼ PaddingObfuscator::obfuscate()
追加随机 Padding（可选）
    │
    ▼ WebSocketObfuscator::obfuscate()
封装为 WebSocket 二进制帧（可选）
    │
    ▼ HttpObfuscator::obfuscate()
包装为 HTTP POST 请求（可选）
    │
    ▼ TCP 发送（4字节长度前缀 + 数据）
到达服务端，逆序拆包解混淆解密，写入 TUN
```

---

## 目录结构

```
vpntunnel/
├── CMakeLists.txt              # CMake 构建脚本
├── build_linux.sh              # Linux 一键构建脚本
├── build_windows.bat           # Windows 一键构建脚本
├── config/
│   ├── server.yaml             # 服务端配置示例
│   └── client.yaml             # 客户端配置示例
├── include/                    # 公共头文件
│   ├── common/
│   │   ├── config.hpp          # 配置结构体，YAML 解析
│   │   ├── logger.hpp          # spdlog 日志封装
│   │   └── packet.hpp          # 数据包结构（握手/数据/keepalive）
│   ├── crypto/
│   │   ├── icrypto.hpp         # 加密接口（两步握手）
│   │   ├── chacha20_crypto.hpp # ChaCha20-Poly1305 实现
│   │   └── aes_gcm_crypto.hpp  # AES-256-GCM 实现
│   ├── obfuscate/
│   │   ├── iobfuscator.hpp     # 混淆接口
│   │   ├── http_obfuscator.hpp # HTTP 伪装
│   │   ├── websocket_obfuscator.hpp # WebSocket 帧混淆
│   │   └── padding_obfuscator.hpp   # 随机 Padding + 流量整形
│   ├── tun/
│   │   ├── itun.hpp            # TUN 设备接口
│   │   ├── linux_tun.hpp       # Linux /dev/net/tun
│   │   └── windows_tun.hpp     # Windows WinTun 动态加载
│   ├── tunnel/
│   │   ├── session.hpp         # 会话（防重放、混淆链）
│   │   └── tunnel_manager.hpp  # 会话管理器
│   └── web/
│       └── web_ui.hpp          # 内置 Web UI 控制台
└── src/                        # 源文件实现（对应 include/ 结构）
    ├── common/
    ├── crypto/
    ├── obfuscate/
    ├── tun/
    ├── tunnel/
    ├── web/
    │   └── web_ui.cpp          # Web UI 控制台实现
    ├── server/
    │   ├── server.hpp          # Server 类（仅 Linux）
    │   ├── server.cpp
    │   └── main_server.cpp     # 服务端入口
    └── client/
        ├── client.hpp          # Client 类（Linux + Windows）
        ├── client.cpp
        └── main_client.cpp     # 客户端入口
```

---

## 依赖要求

### 所有平台

| 依赖 | 版本要求 | 说明 |
|------|---------|------|
| CMake | ≥ 3.16 | 构建系统 |
| C++ 编译器 | C++17 | GCC ≥ 9 / Clang ≥ 10 / MSVC 2019+ |
| OpenSSL | ≥ 3.0 | 提供加密原语（X25519、HKDF、ChaCha20、AES-GCM） |
| Git | 任意版本 | FetchContent 自动拉取第三方库 |

> CMake FetchContent 会自动下载以下库，**无需手动安装**：
> - [Asio](https://github.com/chriskohlhoff/asio) v1.30.2（standalone，header-only）
> - [spdlog](https://github.com/gabime/spdlog) v1.14.1
> - [yaml-cpp](https://github.com/jbeder/yaml-cpp) v0.8.0

### Linux 额外要求

```
libssl-dev（OpenSSL 开发包）
```

### Windows 客户端额外要求

- [WinTun](https://www.wintun.net/) — 下载 `wintun.dll`（与架构匹配的版本），放置于可执行文件同目录
- 以**管理员权限**运行客户端（WinTun 创建网络适配器需要提权）

---

## 编译构建

### Linux（服务端 + 客户端）

**1. 安装系统依赖**

```bash
# Ubuntu / Debian
sudo apt update && sudo apt install -y \
    build-essential cmake git libssl-dev

# CentOS / RHEL
sudo yum install -y gcc-c++ cmake git openssl-devel

# Arch Linux
sudo pacman -S gcc cmake git openssl
```

**2. 克隆仓库**

```bash
git clone https://github.com/ahmatjanmahsut/private-stuf.git
cd private-stuf/vpntunnel
```

**3. 编译**

```bash
chmod +x build_linux.sh
./build_linux.sh
```

或手动执行：

```bash
mkdir -p build_linux && cd build_linux
cmake .. -DCMAKE_BUILD_TYPE=Release
make -j$(nproc)
```

编译成功后，在 `build_linux/` 目录生成：
- `vpn_server` — 服务端可执行文件
- `vpn_client` — Linux 客户端可执行文件

---

### Windows（仅客户端）

**1. 安装依赖**

- [Visual Studio 2019/2022](https://visualstudio.microsoft.com/)，安装"使用 C++ 的桌面开发"工作负载
- [CMake](https://cmake.org/download/)（安装时勾选添加到 PATH）
- [OpenSSL for Windows](https://slproweb.com/products/Win32OpenSSL.html)：安装 Win64 OpenSSL v3.x，默认路径 `C:\Program Files\OpenSSL-Win64`

**2. 克隆仓库**

```bat
git clone https://github.com/ahmatjanmahsut/private-stuf.git
cd private-stuf\vpntunnel
```

**3. 编译**

```bat
build_windows.bat
```

或使用 Developer Command Prompt：

```bat
mkdir build_windows && cd build_windows
cmake .. -DCMAKE_BUILD_TYPE=Release -A x64
cmake --build . --config Release
```

编译成功后，在 `build_windows\Release\` 目录生成：
- `vpn_client.exe`

**4. 准备 WinTun**

从 [https://www.wintun.net/](https://www.wintun.net/) 下载 WinTun 压缩包，解压后将对应架构的 `wintun.dll` 复制到 `build_windows\Release\`：

```
build_windows\Release\
  vpn_client.exe
  wintun.dll        ← 必须放这里
```

---

## Web UI 控制台

项目现已内置 `Web UI`。`vpn_server` 与 `vpn_client` 都支持在浏览器中完成以下操作：

- 启动隧道 / 停止隧道 / 重启隧道
- 从磁盘重新加载配置
- 保存全部配置到 YAML 文件
- 修改加密算法、`PSK`、混淆链顺序
- 修改 `TUN` 地址、掩码、`MTU`
- 修改日志级别、握手超时、`Keepalive`
- 修改 `Web UI` 自身的启用状态、监听地址、端口与自动启动开关

### 默认行为

示例 `config/server.yaml` 与 `config/client.yaml` 已默认开启 `Web UI`，并设置：

- 服务端 Web UI：`http://127.0.0.1:8080`
- 客户端 Web UI：`http://127.0.0.1:8081`
- `auto_start_tunnel: true`，因此进程启动后会自动拉起隧道

如果你希望恢复传统命令行直启模式，可在配置中将 `web_ui.enabled` 设为 `false`，或在启动时传入 `--no-web-ui`。

### 启动方式

```bash
# 服务端：按配置启动 Web UI（若 auto_start_tunnel=true，会自动拉起隧道）
./vpn_server config/server.yaml

# 服务端：强制开启 Web UI，并改监听地址/端口
./vpn_server --config config/server.yaml --web-ui --web-ui-host 0.0.0.0 --web-ui-port 8088

# 客户端：按配置启动 Web UI
./vpn_client config/client.yaml

# 客户端：仅命令行运行，不启动 Web UI
./vpn_client --config config/client.yaml --no-web-ui
```

Windows 客户端同理：

```bat
vpn_client.exe config\client.yaml
vpn_client.exe --config config\client.yaml --web-ui --web-ui-port 8089
```

### 安全建议

- 默认将 Web UI 绑定到 `127.0.0.1`，避免直接暴露到公网。
- 若需远程访问，建议通过 SSH 隧道、反向代理 Basic Auth、Nginx 访问控制或防火墙白名单保护。
- 修改 `web_ui.host` / `web_ui.port` 后，需要重启进程，新的绑定地址才会生效。

---

## 部署教程


### 第一步：服务端部署（Linux）

> 假设服务器公网 IP 为 `1.2.3.4`，操作系统 Ubuntu 22.04。

#### 1.1 上传可执行文件

```bash
# 在编译机上将二进制和配置上传到服务器
scp build_linux/vpn_server root@1.2.3.4:/opt/vpntunnel/
scp config/server.yaml     root@1.2.3.4:/opt/vpntunnel/
```

#### 1.2 修改服务端配置

```bash
ssh root@1.2.3.4
nano /opt/vpntunnel/server.yaml
```

修改以下关键项：

```yaml
role: server

listen:
  host: "0.0.0.0"
  port: 51820            # 监听端口，按需修改

cipher: chacha20-poly1305  # 或 aes-256-gcm

# ⚠️ 务必修改为强随机字符串，与客户端保持一致
psk: "你的强预共享密钥_至少32字符"

obfuscate_chain:
  - padding
  - websocket            # 混淆链，客户端必须与此完全一致

tun:
  name: "tun0"
  address: "10.0.0.1"   # 服务端 TUN IP
  netmask: "255.255.255.0"
  mtu: 1420

web_ui:
  enabled: true
  host: "127.0.0.1"
  port: 8080
  auto_start_tunnel: true
```

#### 1.3 开放防火墙端口

```bash
# UFW
sudo ufw allow 51820/tcp

# firewalld
sudo firewall-cmd --permanent --add-port=51820/tcp
sudo firewall-cmd --reload

# iptables
sudo iptables -A INPUT -p tcp --dport 51820 -j ACCEPT
```

#### 1.4 启用 IP 转发

```bash
# 临时启用
echo 1 | sudo tee /proc/sys/net/ipv4/ip_forward

# 永久生效
echo "net.ipv4.ip_forward = 1" | sudo tee -a /etc/sysctl.conf
sudo sysctl -p
```

#### 1.5 配置 NAT（让客户端流量通过服务器出口上网）

```bash
# 查询服务器出口网卡名（通常是 eth0 或 ens3）
ip route | grep default

# 设置 NAT 转发（将 eth0 替换为你的出口网卡）
sudo iptables -t nat -A POSTROUTING -s 10.0.0.0/24 -o eth0 -j MASQUERADE

# 持久化 iptables 规则
sudo apt install iptables-persistent
sudo netfilter-persistent save
```

#### 1.6 启动服务端

```bash
cd /opt/vpntunnel
# 需要 root 权限操作 TUN 设备
sudo ./vpn_server server.yaml
```

**设置为系统服务（推荐）：**

```bash
sudo tee /etc/systemd/system/vpntunnel.service > /dev/null <<EOF
[Unit]
Description=VPN Tunnel Server
After=network.target

[Service]
Type=simple
User=root
WorkingDirectory=/opt/vpntunnel
ExecStart=/opt/vpntunnel/vpn_server /opt/vpntunnel/server.yaml
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
EOF

sudo systemctl daemon-reload
sudo systemctl enable vpntunnel
sudo systemctl start vpntunnel

# 查看状态
sudo systemctl status vpntunnel
```

---

### 第二步：客户端部署（Linux）

#### 2.1 复制可执行文件和配置

```bash
mkdir -p ~/vpntunnel
cp build_linux/vpn_client ~/vpntunnel/
cp config/client.yaml     ~/vpntunnel/
```

#### 2.2 修改客户端配置

```bash
nano ~/vpntunnel/client.yaml
```

```yaml
role: client

peer:
  host: "1.2.3.4"       # ← 填写服务器公网 IP
  port: 51820            # ← 与服务端一致

cipher: chacha20-poly1305  # ← 必须与服务端一致

psk: "你的强预共享密钥_至少32字符"  # ← 必须与服务端完全一致

obfuscate_chain:
  - padding
  - websocket            # ← 必须与服务端完全一致，顺序相同

tun:
  name: "tun0"
  address: "10.0.0.2"   # ← 每个客户端分配不同 IP（避免冲突）
  netmask: "255.255.255.0"
  mtu: 1420
```

#### 2.3 启动客户端

```bash
cd ~/vpntunnel
sudo ./vpn_client client.yaml
```

---

### 第三步：客户端部署（Windows）

#### 3.1 准备文件

将以下文件放到同一目录，例如 `C:\vpntunnel\`：

```
C:\vpntunnel\
  vpn_client.exe
  wintun.dll
  client.yaml
```

#### 3.2 修改客户端配置

用文本编辑器打开 `client.yaml`，填写与 Linux 客户端相同的服务端 IP、PSK 和混淆链。

TUN 地址分配不同 IP，避免与其他客户端冲突：

```yaml
tun:
  name: "vpntun"       # Windows 下适配器名称
  address: "10.0.0.3"  # 与其他客户端不同
```

#### 3.3 以管理员权限启动

右键 `cmd.exe` → **以管理员身份运行**，然后：

```bat
cd C:\vpntunnel
vpn_client.exe client.yaml
```

或创建快捷方式，右键 → 属性 → 高级 → 勾选"以管理员身份运行"。

---

### 第四步：验证连通性

#### 验证 TUN 接口建立

**Linux：**
```bash
ip addr show tun0
# 应看到 inet 10.0.0.x/24 的 TUN 接口
```

**Windows：**
```bat
ipconfig
# 应看到名为 vpntun 的虚拟适配器，IP 为 10.0.0.x
```

#### 验证隧道连通

```bash
# 客户端 ping 服务端 TUN IP
ping 10.0.0.1

# 服务端 ping 客户端 TUN IP
ping 10.0.0.2
```

#### 查看服务端日志

```bash
sudo journalctl -u vpntunnel -f
# 或直接看控制台输出：
# [2026-04-07 10:00:00.000] [info] Server listening on 0.0.0.0:51820
# [2026-04-07 10:00:05.123] [info] New connection from 5.6.7.8
# [2026-04-07 10:00:05.234] [info] Handshake complete, session_id=1
```

---

## 配置文件说明

### 服务端配置

```yaml
# config/server.yaml

role: server

listen:
  host: "0.0.0.0"   # 监听所有网卡，可改为指定 IP
  port: 51820        # 监听端口

cipher: chacha20-poly1305   # 加密算法

psk: "change-this-to-a-strong-secret-key"  # 预共享密钥

obfuscate_chain:
  - padding     # 第一层：随机 Padding
  - websocket   # 第二层：WebSocket 帧

tun:
  name: "tun0"
  address: "10.0.0.1"
  netmask: "255.255.255.0"
  mtu: 1420

log_level: 1           # 0=trace 1=info 2=warn 3=error
handshake_timeout: 5   # 握手超时（秒）
keepalive_interval: 25 # Keepalive 间隔（秒）
```

### 客户端配置

```yaml
# config/client.yaml

role: client

peer:
  host: "YOUR_SERVER_IP"  # 服务端公网 IP 或域名
  port: 51820

cipher: chacha20-poly1305  # 必须与服务端一致

psk: "change-this-to-a-strong-secret-key"  # 必须与服务端一致

obfuscate_chain:
  - padding
  - websocket   # 必须与服务端一致，顺序相同

tun:
  name: "tun0"
  address: "10.0.0.2"    # 每个客户端分配不同 IP
  netmask: "255.255.255.0"
  mtu: 1420

log_level: 1
handshake_timeout: 5
keepalive_interval: 25
```

### 配置项详解

| 字段 | 类型 | 说明 |
|------|------|------|
| `role` | string | `server` 或 `client` |
| `listen.host` | string | 服务端监听地址 |
| `listen.port` | int | 服务端监听端口（默认 51820） |
| `peer.host` | string | 客户端填写服务端 IP/域名 |
| `peer.port` | int | 客户端填写服务端端口 |
| `cipher` | string | `chacha20-poly1305` 或 `aes-256-gcm` |
| `psk` | string | 预共享密钥，双端必须完全一致 |
| `obfuscate_chain` | list | 混淆链，双端顺序必须完全一致 |
| `tun.name` | string | TUN 设备名 |
| `tun.address` | string | TUN 接口 IP，每客户端唯一 |
| `tun.netmask` | string | 子网掩码 |
| `tun.mtu` | int | MTU，建议 1420（避免分片） |
| `log_level` | int | 0=trace 1=info 2=warn 3=error |
| `handshake_timeout` | int | 握手超时秒数 |
| `keepalive_interval` | int | Keepalive 心跳间隔秒数 |

---

## 混淆模式说明

支持三种混淆模式，可在 `obfuscate_chain` 中任意组合，按列表顺序依次叠加。

### HTTP 伪装（`http`）

将数据包装为标准 HTTP POST 请求：

```
POST /api/data HTTP/1.1
Host: www.example.com
Content-Type: application/octet-stream
Content-Length: <len>

<加密数据>
```

- 适用场景：绕过仅允许 HTTP 流量的防火墙
- 接收端自动剥除 HTTP 头部还原数据

### WebSocket 帧混淆（`websocket`）

按 RFC 6455 标准封装 WebSocket 二进制帧：

```
FIN=1, Opcode=0x2 (Binary)
MASK=1, 随机 4 字节掩码
Payload = 原始数据 XOR 掩码
```

- 适用场景：伪装为 WebSocket 长连接流量
- 支持 payload 长度 < 126 / < 65536 / ≥ 65536 三种编码

### 随机 Padding + 流量整形（`padding`）

```
[原始数据长度 4字节 LE][原始数据][随机填充 0~255 字节]
```

- 随机追加 0~255 字节垃圾数据，破坏流量特征
- 可配置随机微秒延迟，对抗基于时序的流量分析
- 接收端读取前 4 字节获取真实长度，自动截断

### 推荐组合

| 场景 | 推荐配置 |
|------|---------|
| 标准使用 | `padding` → `websocket` |
| 强隐蔽需求 | `padding` → `websocket` → `http` |
| 最低延迟 | 不配置混淆（`obfuscate_chain: []`） |

> **注意：** 双端 `obfuscate_chain` 必须完全一致，顺序不能颠倒。

---

## 加密方案说明

### ChaCha20-Poly1305（默认推荐）

- 流密码 + AEAD 认证，无需硬件加速即可达到高性能
- 对 ARM/移动设备友好，抗 timing attack
- 同 WireGuard 使用的加密算法

### AES-256-GCM

- 工业标准对称加密，x86/x64 平台有 AES-NI 硬件加速
- 128-bit GCM 认证标签，256-bit 密钥
- 适合服务器端 CPU 支持 AES-NI 的场景

### 会话密钥推导流程

```
1. 双端各自生成 X25519 临时密钥对
2. 交换公钥（握手包 HMAC-SHA256 验证完整性）
3. X25519 ECDH 计算共享密钥 shared_secret（32 字节）
4. HKDF-SHA256(ikm=shared_secret, salt=握手nonce, info="vpntunnel-chacha20")
5. 输出 32 字节会话密钥，用于后续所有数据加密
```

每次握手产生唯一会话密钥，前向保密（PFS）。

---

## 握手协议流程

```
客户端                                              服务端
  │                                                  │
  │── [1] HandshakeInit ──────────────────────────►  │
  │      type=0x01                                   │
  │      sender_pubkey[32]  ← X25519 临时公钥        │
  │      nonce[12]          ← 随机 HKDF salt         │
  │      hmac[32]           ← HMAC-SHA256(PSK)       │
  │                                                  │
  │  ◄─────────────────────── [2] HandshakeResp ──── │
  │      type=0x02                                   │
  │      session_id[4]      ← 服务端分配的会话 ID    │
  │      sender_pubkey[32]  ← 服务端 X25519 临时公钥 │
  │      nonce[12]          ← 随机                   │
  │      hmac[32]           ← HMAC-SHA256(PSK)       │
  │                                                  │
  │  双端独立完成 ECDH + HKDF，推导相同会话密钥       │
  │                                                  │
  │── [3] DataPacket（加密 + 混淆）─────────────────► │
  │      type=0x03                                   │
  │      session_id[4]                               │
  │      seq[8]             ← 单调递增 nonce 计数器  │
  │      ciphertext_len[4]                           │
  │      ciphertext[...]    ← AEAD 密文 + 16字节 tag │
  │                                                  │
  │  ◄──────────────────────────── DataPacket ────── │
```

---

## 安全性说明

- **PSK 强度**：`psk` 应使用至少 32 字节的随机字符串，可用以下命令生成：
  ```bash
  openssl rand -base64 32
  ```
- **不在配置文件中明文存储密钥**（生产环境建议使用环境变量或密钥管理服务）
- **防重放窗口**：256 个序列号的滑动窗口，拒绝重复或过旧的数据包
- **前向保密**：每次握手生成全新 X25519 临时密钥对，历史会话密钥不可恢复
- **AEAD 完整性**：ChaCha20-Poly1305 / AES-256-GCM 均提供 16 字节认证标签，任何篡改均被检测

---

## 常见问题

### Q: 服务端启动报 "Failed to open /dev/net/tun"

需要 root 权限，或确认内核已加载 TUN 模块：

```bash
sudo modprobe tun
sudo ./vpn_server server.yaml
```

### Q: 客户端提示 "Cannot connect to server"

1. 检查服务端防火墙是否放通了对应 TCP 端口
2. 检查 `client.yaml` 中 `peer.host` 是否为正确的公网 IP
3. 尝试 `telnet 1.2.3.4 51820` 验证网络连通性

### Q: Windows 客户端报 "Failed to load wintun.dll"

确认 `wintun.dll` 与 `vpn_client.exe` 在同一目录，且架构匹配（x64 程序需要 x64 的 dll）。

### Q: 双端 ping 通但上网不通

确认服务端已开启 IP 转发并配置了 NAT 规则：

```bash
# 检查 IP 转发
cat /proc/sys/net/ipv4/ip_forward   # 应为 1

# 检查 NAT 规则
sudo iptables -t nat -L POSTROUTING -n -v
```

### Q: 连接不稳定，频繁断开

- 调小 `keepalive_interval`（如改为 10）
- 检查服务器负载和网络质量
- 开启 `log_level: 0`（trace 级别）查看详细日志

### Q: 如何多客户端同时连接？

每个客户端在 `client.yaml` 中配置不同的 `tun.address`：

```
客户端1: 10.0.0.2
客户端2: 10.0.0.3
客户端3: 10.0.0.4
```

---

## 许可证

本项目仅供学习和研究使用。请遵守所在地区的法律法规，不得将本软件用于任何违法用途。
