#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

cd "${ROOT_DIR}"
gcc -O3 -funroll-loops ./neuzz.c -o neuzz
echo "Built ${ROOT_DIR}/neuzz"
