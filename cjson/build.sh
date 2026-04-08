#!/bin/bash
# Build cjson_driver in all three variants.
# Run this on Linux after cloning cJSON source files into this directory.
#
# Prerequisites:
#   sudo apt install gcc afl++ build-essential
#   wget https://raw.githubusercontent.com/DaveGamble/cJSON/master/cJSON.c
#   wget https://raw.githubusercontent.com/DaveGamble/cJSON/master/cJSON.h

set -e
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
cd "$SCRIPT_DIR"

if [ ! -f cJSON.c ] || [ ! -f cJSON.h ]; then
    echo "[*] Downloading cJSON source..."
    wget -q https://raw.githubusercontent.com/DaveGamble/cJSON/master/cJSON.c
    wget -q https://raw.githubusercontent.com/DaveGamble/cJSON/master/cJSON.h
fi

echo "[*] Building plain binary (for your fuzzer)..."
gcc cjson_driver.c cJSON.c -o cjson_driver -I. -lm
echo "    -> cjson_driver"

echo "[*] Building AFL++ instrumented binary..."
if command -v afl-clang-fast &>/dev/null; then
    afl-clang-fast cjson_driver.c cJSON.c -o cjson_driver_afl -I. -lm
    echo "    -> cjson_driver_afl (afl-clang-fast)"
elif command -v afl-gcc-fast &>/dev/null; then
    afl-gcc-fast cjson_driver.c cJSON.c -o cjson_driver_afl -I. -lm
    echo "    -> cjson_driver_afl (afl-gcc-fast)"
else
    echo "    [!] afl-clang-fast/afl-gcc-fast not found — skipping AFL build"
fi

echo "[*] Building ASAN binary (crash detection)..."
gcc cjson_driver.c cJSON.c -o cjson_driver_asan -I. -lm \
    -fsanitize=address,undefined -fno-omit-frame-pointer
echo "    -> cjson_driver_asan"

echo "[*] Done."
