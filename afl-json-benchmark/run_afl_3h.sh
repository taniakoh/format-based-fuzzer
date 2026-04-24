#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
INPUT_DIR="${ROOT_DIR}/afl_in"
OUTPUT_DIR="${ROOT_DIR}/afl-out"
PYTHON_BIN="${ROOT_DIR}/.venv/bin/python"
AFL_BIN="${ROOT_DIR}/.venv/bin/py-afl-fuzz"

mkdir -p "${OUTPUT_DIR}"

AFL_I_DONT_CARE_ABOUT_MISSING_CRASHES=1 \
timeout 10800s \
"${AFL_BIN}" -i "${INPUT_DIR}" -o "${OUTPUT_DIR}" -- "${PYTHON_BIN}" "${ROOT_DIR}/afl_json_harness.py"
