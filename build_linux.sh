#!/usr/bin/env bash
# Build script for Linux (server + client)
set -e

BUILD_DIR="build_linux"
cmake -B "$BUILD_DIR" -S . \
    -DCMAKE_BUILD_TYPE=Release \
    -DCMAKE_EXPORT_COMPILE_COMMANDS=ON

cmake --build "$BUILD_DIR" --parallel "$(nproc)"

echo ""
echo "Build complete:"
echo "  Server:  $BUILD_DIR/vpn_server"
echo "  Client:  $BUILD_DIR/vpn_client"
echo ""
echo "Usage:"
echo "  sudo ./$BUILD_DIR/vpn_server [config/server.yaml]"
echo "  sudo ./$BUILD_DIR/vpn_client [config/client.yaml]"
