cmake_minimum_required(VERSION 3.16)
project(vpntunnel VERSION 1.0.0 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

# ── 编译选项 ────────────────────────────────────────────────────────────────
if(MSVC)
    add_compile_options(/W4 /utf-8)
else()
    add_compile_options(-Wall -Wextra -Wpedantic)
endif()

# ── 第三方依赖（FetchContent）───────────────────────────────────────────────
include(FetchContent)

# asio (standalone, header-only)
FetchContent_Declare(asio
    GIT_REPOSITORY https://github.com/chriskohlhoff/asio.git
    GIT_TAG        asio-1-30-2
    GIT_SHALLOW    TRUE
)
FetchContent_MakeAvailable(asio)
add_library(asio_lib INTERFACE)
target_include_directories(asio_lib INTERFACE ${asio_SOURCE_DIR}/asio/include)
target_compile_definitions(asio_lib INTERFACE ASIO_STANDALONE)
if(WIN32)
    target_link_libraries(asio_lib INTERFACE ws2_32 wsock32)
endif()

# spdlog (header-only)
FetchContent_Declare(spdlog
    GIT_REPOSITORY https://github.com/gabime/spdlog.git
    GIT_TAG        v1.14.1
    GIT_SHALLOW    TRUE
)
FetchContent_MakeAvailable(spdlog)

# yaml-cpp
FetchContent_Declare(yaml-cpp
    GIT_REPOSITORY https://github.com/jbeder/yaml-cpp.git
    GIT_TAG        0.8.0
    GIT_SHALLOW    TRUE
)
set(YAML_CPP_BUILD_TESTS   OFF CACHE BOOL "" FORCE)
set(YAML_CPP_BUILD_TOOLS   OFF CACHE BOOL "" FORCE)
set(YAML_CPP_BUILD_CONTRIB OFF CACHE BOOL "" FORCE)
FetchContent_MakeAvailable(yaml-cpp)

# ── OpenSSL ─────────────────────────────────────────────────────────────────
find_package(OpenSSL REQUIRED)

# ── 公共 include 目录 ────────────────────────────────────────────────────────
set(COMMON_INCLUDE_DIR ${CMAKE_SOURCE_DIR}/include)

# ── 共享源文件（common / crypto / obfuscate / tun / tunnel）─────────────────
set(COMMON_SOURCES
    src/common/config.cpp
    src/common/logger.cpp
    src/crypto/chacha20_crypto.cpp
    src/crypto/aes_gcm_crypto.cpp
    src/obfuscate/http_obfuscator.cpp
    src/obfuscate/websocket_obfuscator.cpp
    src/obfuscate/padding_obfuscator.cpp
    src/tun/linux_tun.cpp
    src/tunnel/session.cpp
    src/tunnel/tunnel_manager.cpp
)

# Windows 客户端额外加 windows_tun.cpp
set(CLIENT_TUN_SOURCES)
if(WIN32)
    list(APPEND CLIENT_TUN_SOURCES src/tun/windows_tun.cpp)
endif()

# ── 公共链接库 ────────────────────────────────────────────────────────────────
set(COMMON_LIBS
    asio_lib
    spdlog::spdlog_header_only
    yaml-cpp::yaml-cpp
    OpenSSL::SSL
    OpenSSL::Crypto
)
if(UNIX)
    list(APPEND COMMON_LIBS pthread)
endif()

# ── server 可执行文件（仅 Linux 构建）────────────────────────────────────────
if(UNIX AND NOT APPLE)
    add_executable(vpn_server
        ${COMMON_SOURCES}
        src/server/server.cpp
        src/server/main_server.cpp
    )
    target_include_directories(vpn_server PRIVATE ${COMMON_INCLUDE_DIR})
    target_link_libraries(vpn_server PRIVATE ${COMMON_LIBS})
    target_compile_definitions(vpn_server PRIVATE VPN_SERVER_BUILD)
    install(TARGETS vpn_server RUNTIME DESTINATION bin)
endif()

# ── client 可执行文件（Linux + Windows）──────────────────────────────────────
add_executable(vpn_client
    ${COMMON_SOURCES}
    ${CLIENT_TUN_SOURCES}
    src/client/client.cpp
    src/client/main_client.cpp
)
target_include_directories(vpn_client PRIVATE ${COMMON_INCLUDE_DIR})
target_link_libraries(vpn_client PRIVATE ${COMMON_LIBS})
target_compile_definitions(vpn_client PRIVATE VPN_CLIENT_BUILD)
if(WIN32)
    target_compile_definitions(vpn_client PRIVATE WIN32_LEAN_AND_MEAN NOMINMAX)
endif()
install(TARGETS vpn_client RUNTIME DESTINATION bin)
