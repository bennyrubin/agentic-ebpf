#!/usr/bin/env bash
set -euo pipefail

ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
BIN_DIR="${BIN_DIR:-$ROOT/bin}"
SETUPDB_BIN="${SETUPDB_BIN:-$BIN_DIR/setupdb}"

DB_PATH="$ROOT/pebble.data"
NUM_KEYS=10000
VALUE_BYTES=256
KEY_PREFIX="key"
DESTROY="false"
NEED_LOAD="true"

usage() {
  cat <<USAGE
Usage: $0 [options]
  -d <path>   Pebble directory (default: $DB_PATH)
  -n <int>    number of keys (default: $NUM_KEYS)
  -s <int>    value size in bytes (default: $VALUE_BYTES)
  -p <str>    key prefix (default: $KEY_PREFIX)
  -x          destroy existing database before loading
USAGE
}

while getopts ":d:n:s:p:x" opt; do
  case "$opt" in
    d) DB_PATH="$OPTARG" ;;
    n) NUM_KEYS="$OPTARG" ;;
    s) VALUE_BYTES="$OPTARG" ;;
    p) KEY_PREFIX="$OPTARG" ;;
    x) DESTROY="true" ;;
    :) echo "Option -$OPTARG requires an argument." >&2; exit 1 ;;
    \?) usage; exit 1 ;;
  esac
done

META_FILE="$DB_PATH/.dataset_meta"

if [[ "$DESTROY" != "true" ]]; then
  if [[ -d "$DB_PATH" && -f "$META_FILE" ]]; then
    # shellcheck disable=SC1090
    source "$META_FILE"
    if [[ "${DATASET_KEYS:-}" == "$NUM_KEYS" && \
          "${DATASET_VALUE_BYTES:-}" == "$VALUE_BYTES" && \
          "${DATASET_KEY_PREFIX:-}" == "$KEY_PREFIX" ]]; then
      NEED_LOAD="false"
    fi
  fi
fi

if [[ "$NEED_LOAD" == "false" ]]; then
  echo "Dataset already populated (keys=$NUM_KEYS value_bytes=$VALUE_BYTES prefix=$KEY_PREFIX); skipping load."
  exit 0
fi

if [[ -x "$SETUPDB_BIN" ]]; then
  CMD=("$SETUPDB_BIN" -db "$DB_PATH" -keys "$NUM_KEYS" -value-bytes "$VALUE_BYTES" -key-prefix "$KEY_PREFIX")
else
  CMD=(go run ./cmd/setupdb -db "$DB_PATH" -keys "$NUM_KEYS" -value-bytes "$VALUE_BYTES" -key-prefix "$KEY_PREFIX")
fi
if [[ "$DESTROY" == "true" ]]; then
  CMD+=( -destroy )
fi

pushd "$ROOT" >/dev/null
"${CMD[@]}"
popd >/dev/null

mkdir -p "$DB_PATH"
{
  echo "DATASET_KEYS=$NUM_KEYS"
  echo "DATASET_VALUE_BYTES=$VALUE_BYTES"
  printf 'DATASET_KEY_PREFIX=%q\n' "$KEY_PREFIX"
} > "$META_FILE"
