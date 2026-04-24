#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
INPUT_DIR="${ROOT_DIR}/neuzz_in"
LOG_DIR="${ROOT_DIR}/logs"
RESULTS_DIR="${ROOT_DIR}/results"
PYTHON_BIN="python3"
DURATION_SECONDS="${NEUZZ_BENCHMARK_SECONDS:-3600}"

if [[ -x "${ROOT_DIR}/.venv/bin/python" ]]; then
  PYTHON_BIN="./.venv/bin/python"
fi

mkdir -p "${LOG_DIR}" "${RESULTS_DIR}"

if [[ ! -x "${ROOT_DIR}/neuzz" ]]; then
  echo "Neuzz binary not found. Run ./build_neuzz.sh first."
  exit 1
fi

if [[ ! -d "${INPUT_DIR}" ]] || [[ -z "$(find "${INPUT_DIR}" -maxdepth 1 -type f -print -quit)" ]]; then
  echo "Seed corpus missing. Run python3 prepare_seed_corpus.py first."
  exit 1
fi

MAX_FILE_SIZE="$("${PYTHON_BIN}" -c 'from pathlib import Path; import sys; root = Path(sys.argv[1]); sizes = [p.stat().st_size for p in root.iterdir() if p.is_file()]; print(max(sizes) if sizes else 1)' "${INPUT_DIR}")"

rm -rf "${ROOT_DIR}/seeds" "${ROOT_DIR}/bitmaps" "${ROOT_DIR}/splice_seeds" "${ROOT_DIR}/vari_seeds" "${ROOT_DIR}/crashes"
mkdir -p "${ROOT_DIR}/seeds" "${RESULTS_DIR}"

export AFL_MAP_SIZE=524288
export NEUZZ_JSON_RESULTS_DIR="${RESULTS_DIR}"
export NEUZZ_JSON_TIMEOUT_SECONDS="${NEUZZ_JSON_TIMEOUT_SECONDS:-3}"
export PYTHONPATH="${ROOT_DIR}:${PYTHONPATH:-}"

pkill -f "${ROOT_DIR}/nn.py" >/dev/null 2>&1 || true
if command -v fuser >/dev/null 2>&1; then
  fuser -k 12012/tcp >/dev/null 2>&1 || true
fi

cleanup() {
  if [[ -n "${MONITOR_PID:-}" ]]; then
    kill "${MONITOR_PID}" >/dev/null 2>&1 || true
    wait "${MONITOR_PID}" 2>/dev/null || true
  fi
  if [[ -n "${NN_PID:-}" ]]; then
    kill "${NN_PID}" >/dev/null 2>&1 || true
    wait "${NN_PID}" 2>/dev/null || true
  fi
}
trap cleanup EXIT

"${PYTHON_BIN}" "${ROOT_DIR}/nn.py" "${PYTHON_BIN}" "${ROOT_DIR}/neuzz_json_target.py" > "${LOG_DIR}/nn.log" 2>&1 &
NN_PID=$!

for _ in $(seq 1 60); do
  if ! kill -0 "${NN_PID}" >/dev/null 2>&1; then
    echo "Neuzz trainer exited before opening its socket. Check ${LOG_DIR}/nn.log."
    exit 1
  fi
  if ss -ltn 2>/dev/null | grep -q ':12012 '; then
    break
  fi
  sleep 1
done

if ! ss -ltn 2>/dev/null | grep -q ':12012 '; then
  echo "Neuzz trainer did not open port 12012 in time. Check ${LOG_DIR}/nn.log."
  exit 1
fi

echo "Starting Neuzz for ${DURATION_SECONDS} seconds. Live progress will refresh below. Raw logs are in ${LOG_DIR}/."

timeout "${DURATION_SECONDS}s" "${ROOT_DIR}/neuzz" -i "${INPUT_DIR}" -o seeds -l "${MAX_FILE_SIZE}" "${PYTHON_BIN}" "${ROOT_DIR}/neuzz_json_target.py" @@ > "${LOG_DIR}/neuzz.log" 2>&1 &
NEUZZ_PID=$!

"${PYTHON_BIN}" "${ROOT_DIR}/monitor_neuzz_progress.py" --workspace "${ROOT_DIR}" --pid "${NEUZZ_PID}" &
MONITOR_PID=$!

wait "${NEUZZ_PID}"
