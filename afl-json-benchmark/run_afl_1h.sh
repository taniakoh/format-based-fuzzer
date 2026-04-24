#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
INPUT_DIR="${ROOT_DIR}/afl_in"
OUTPUT_DIR="${ROOT_DIR}/afl-out"

mkdir -p "${OUTPUT_DIR}"

timeout 3600s py-afl-fuzz -i "${INPUT_DIR}" -o "${OUTPUT_DIR}" -- python "${ROOT_DIR}/afl_json_harness.py"
