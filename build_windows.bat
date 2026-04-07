@echo off
REM Build script for Windows (client only)
setlocal

set BUILD_DIR=build_windows

cmake -B %BUILD_DIR% -S . ^
    -DCMAKE_BUILD_TYPE=Release ^
    -A x64

cmake --build %BUILD_DIR% --config Release --parallel

echo.
echo Build complete:
echo   Client:  %BUILD_DIR%\Release\vpn_client.exe
echo.
echo Usage:
echo   %BUILD_DIR%\Release\vpn_client.exe [config\client.yaml]
echo.
echo NOTE: Requires wintun.dll in the same directory as vpn_client.exe
echo       Download from https://www.wintun.net/
