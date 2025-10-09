#!/usr/bin/env bash

set -euo pipefail

usage() {
    cat <<'EOF'
Usage: per-connection-workload.sh <total_requests> [options]

Options:
  --mix path:percent[,path:percent...]   Weighted request mix (default: hello:50,cpu:50)
  --base-url URL                         Base URL to target (default: http://localhost:8080)
  --parallel N                           Number of concurrent workers (default: 4)
  --reuse-port PORT                      Force every request to reuse the same local source port
  --sleep-ms N                           Sleep N milliseconds between requests per worker (default: 0)
  -h, --help                             Show this help text and exit

Examples:
  ./per-connection-workload.sh 1000
  ./per-connection-workload.sh 2000 --mix hello:60,cpu:40
  ./per-connection-workload.sh 500 --mix hello:50,cpu:40,other:10 --parallel 8
  ./per-connection-workload.sh 200 --reuse-port 45000
EOF
}

error() {
    echo "Error: $*" >&2
    exit 1
}

trim() {
    local s="$1"
    s="${s#"${s%%[![:space:]]*}"}"
    s="${s%"${s##*[![:space:]]}"}"
    printf '%s' "$s"
}

msleep() {
    local duration_ms="$1"
    if (( duration_ms <= 0 )); then
        return
    fi

    local seconds=$(( duration_ms / 1000 ))
    local remainder=$(( duration_ms % 1000 ))

    if (( remainder > 0 )); then
        local remainder_str
        remainder_str=$(printf "%03d" "$remainder")
        if (( seconds > 0 )); then
            sleep "${seconds}.${remainder_str}"
        else
            sleep "0.${remainder_str}"
        fi
    else
        sleep "$seconds"
    fi
}

declare -a PATHS=()
declare -a PERCENTAGES=()
declare -a CUMULATIVE=()

parse_mix() {
    local spec="$1"
    PATHS=()
    PERCENTAGES=()
    CUMULATIVE=()

    IFS=',' read -ra entries <<< "$spec"
    if (( ${#entries[@]} == 0 )); then
        error "request mix must contain at least one entry"
    fi

    local running=0
    for entry in "${entries[@]}"; do
        entry="$(trim "$entry")"
        [[ -z "$entry" ]] && continue
        if [[ "$entry" != *:* ]]; then
            error "invalid mix entry '$entry' (expected format path:percent)"
        fi

        local path="${entry%%:*}"
        local percent="${entry##*:}"
        path="$(trim "$path")"
        percent="$(trim "$percent")"

        if [[ -z "$path" ]]; then
            error "empty path in mix specification"
        fi
        if [[ "$path" != /* ]]; then
            path="/$path"
        fi
        if ! [[ "$percent" =~ ^[0-9]+$ ]]; then
            error "invalid percentage '$percent' for path '$path'"
        fi

        percent=$((10#$percent))
        if (( percent < 0 || percent > 100 )); then
            error "percentage for path '$path' must be between 0 and 100"
        fi

        running=$((running + percent))
        PATHS+=("$path")
        PERCENTAGES+=("$percent")
        CUMULATIVE+=("$running")
    done

    if (( running != 100 )); then
        error "request mix percentages must add up to 100 (currently $running)"
    fi
}

choose_index() {
    local roll=$(( RANDOM % 100 ))
    local idx
    for idx in "${!CUMULATIVE[@]}"; do
        if (( roll < CUMULATIVE[idx] )); then
            printf '%d' "$idx"
            return
        fi
    done

    printf '%d' $(( ${#CUMULATIVE[@]} - 1 ))
}

TOTAL_REQUESTS=""
BASE_URL="http://localhost:8080"
MIX_SPEC="hello:50,cpu:50"
PARALLEL=4
REUSE_PORT=""
SLEEP_MS=0

if (( $# == 0 )); then
    usage
    exit 1
fi

TOTAL_REQUESTS="$1"
shift

if ! [[ "$TOTAL_REQUESTS" =~ ^[0-9]+$ ]]; then
    error "total_requests must be a positive integer"
fi
TOTAL_REQUESTS=$((10#$TOTAL_REQUESTS))
if (( TOTAL_REQUESTS <= 0 )); then
    error "total_requests must be greater than zero"
fi

while (( $# > 0 )); do
    case "$1" in
        --mix)
            [[ $# -lt 2 ]] && error "--mix requires an argument"
            MIX_SPEC="$2"
            shift 2
            ;;
        --base-url)
            [[ $# -lt 2 ]] && error "--base-url requires an argument"
            BASE_URL="$2"
            shift 2
            ;;
        --parallel)
            [[ $# -lt 2 ]] && error "--parallel requires an argument"
            PARALLEL="$2"
            shift 2
            ;;
        --reuse-port)
            [[ $# -lt 2 ]] && error "--reuse-port requires an argument"
            REUSE_PORT="$2"
            shift 2
            ;;
        --sleep-ms)
            [[ $# -lt 2 ]] && error "--sleep-ms requires an argument"
            SLEEP_MS="$2"
            shift 2
            ;;
        -h|--help)
            usage
            exit 0
            ;;
        *)
            error "unknown option '$1'"
            ;;
    esac
done

if ! command -v curl >/dev/null 2>&1; then
    error "curl is required but was not found in PATH"
fi

BASE_URL="$(trim "$BASE_URL")"
if [[ -z "$BASE_URL" ]]; then
    error "base URL cannot be empty"
fi
BASE_URL="${BASE_URL%/}"

if ! [[ "$PARALLEL" =~ ^[0-9]+$ ]]; then
    error "--parallel must be a positive integer"
fi
PARALLEL=$((10#$PARALLEL))
if (( PARALLEL <= 0 )); then
    error "--parallel must be greater than zero"
fi

if [[ -n "$REUSE_PORT" ]]; then
    if ! [[ "$REUSE_PORT" =~ ^[0-9]+$ ]]; then
        error "--reuse-port expects a numeric TCP port"
    fi
    REUSE_PORT=$((10#$REUSE_PORT))
    if (( REUSE_PORT < 1024 || REUSE_PORT > 65535 )); then
        error "--reuse-port must be between 1024 and 65535"
    fi
fi

if ! [[ "$SLEEP_MS" =~ ^[0-9]+$ ]]; then
    error "--sleep-ms must be a non-negative integer"
fi
SLEEP_MS=$((10#$SLEEP_MS))

parse_mix "$MIX_SPEC"

printf "Launching per-connection workload:\n"
printf "  Total requests : %d\n" "$TOTAL_REQUESTS"
printf "  Workers        : %d\n" "$PARALLEL"
printf "  Base URL       : %s\n" "$BASE_URL"
printf "  Request mix    : "
for idx in "${!PATHS[@]}"; do
    if (( idx > 0 )); then
        printf ", "
    fi
    printf "%s=%d%%" "${PATHS[idx]}" "${PERCENTAGES[idx]}"
done
printf "\n"
if [[ -n "$REUSE_PORT" ]]; then
    printf "  Fixed port     : %d (reused for every request)\n" "$REUSE_PORT"
else
    printf "  Fixed port     : disabled (ephemeral ports)\n"
fi
if (( SLEEP_MS > 0 )); then
    printf "  Sleep          : %d ms between requests per worker\n" "$SLEEP_MS"
else
    printf "  Sleep          : disabled\n"
fi

LOG_ROOT="wrk_log"
mkdir -p "$LOG_ROOT"

LOG_DIR=$(mktemp -d "$LOG_ROOT/per_connection.XXXXXX")
if [[ -z "$LOG_DIR" || ! -d "$LOG_DIR" ]]; then
    error "failed to create log directory under $LOG_ROOT"
fi

printf "Logs will be stored in %s\n" "$LOG_DIR"

curl_base=(curl --http1.1 --no-keepalive --fail -sS -o /dev/null --connect-timeout 2 --max-time 5)
if [[ -n "$REUSE_PORT" ]]; then
    curl_base+=(--local-port "${REUSE_PORT}-${REUSE_PORT}")
fi

run_worker() {
    local worker_id="$1"
    local request_count="$2"

    if (( request_count <= 0 )); then
        return 0
    fi

    local worker_log="$LOG_DIR/worker_${worker_id}.log"
    local summary_file="$LOG_DIR/worker_${worker_id}.summary"
    local success=0
    local failure=0
    local -a index_counts=()

    printf "Worker %s starting (%s requests)\n" "$worker_id" "$request_count" >> "$worker_log"

    for ((i = 1; i <= request_count; i++)); do
        local idx
        idx="$(choose_index)"
        local path="${PATHS[idx]}"
        local url="${BASE_URL}${path}"

        if "${curl_base[@]}" "$url" >>"$worker_log" 2>&1; then
            success=$((success + 1))
        else
            failure=$((failure + 1))
            printf "Request %d to %s failed (worker %s)\n" "$i" "$url" "$worker_id" >>"$worker_log"
        fi

        index_counts[$idx]=$(( ${index_counts[$idx]:-0} + 1 ))

        if (( SLEEP_MS > 0 )); then
            msleep "$SLEEP_MS"
        fi
    done

    {
        printf "success=%d\n" "$success"
        printf "failure=%d\n" "$failure"
        for idx in "${!PATHS[@]}"; do
            printf "path_%d_count=%d\n" "$idx" "${index_counts[$idx]:-0}"
        done
    } >"$summary_file"

    return 0
}

declare -a pids=()
base=$(( TOTAL_REQUESTS / PARALLEL ))
extra=$(( TOTAL_REQUESTS % PARALLEL ))

for ((worker = 0; worker < PARALLEL; worker++)); do
    local_count=$base
    if (( worker < extra )); then
        local_count=$((local_count + 1))
    fi

    if (( local_count <= 0 )); then
        continue
    fi

    run_worker "$worker" "$local_count" &
    pids+=("$!")
done

set +e
worker_failures=0
for pid in "${pids[@]}"; do
    if ! wait "$pid"; then
        worker_failures=1
    fi
done
set -e

total_success=0
total_failure=0
declare -a total_index_counts=()

for summary in "$LOG_DIR"/worker_*.summary; do
    [[ -f "$summary" ]] || continue
    while IFS='=' read -r key value; do
        [[ -z "$key" ]] && continue
        case "$key" in
            success)
                total_success=$((total_success + value))
                ;;
            failure)
                total_failure=$((total_failure + value))
                ;;
            path_*_count)
                idx="${key#path_}"
                idx="${idx%_count}"
                total_index_counts[$idx]=$(( ${total_index_counts[$idx]:-0} + value ))
                ;;
        esac
    done <"$summary"
done

printf "\nRun complete.\n"
printf "  Successful requests : %d\n" "$total_success"
printf "  Failed requests     : %d\n" "$total_failure"
printf "  Total observed      : %d\n" $((total_success + total_failure))

printf "  Observed mix        : "
for idx in "${!PATHS[@]}"; do
    if (( idx > 0 )); then
        printf ", "
    fi
    count=${total_index_counts[$idx]:-0}
    if (( TOTAL_REQUESTS > 0 )); then
        percent=$(( count * 100 / TOTAL_REQUESTS ))
    else
        percent=0
    fi
    printf "%s=%d (%d%%)" "${PATHS[idx]}" "$count" "$percent"
done
printf "\n"

if [[ -n "$REUSE_PORT" ]]; then
    cat <<EOF

Note: reuse-port mode is enabled. Rapidly reusing the same local source port can
lead to HASH collisions or socket exhaustion on the server side and may trigger
additional request failures captured above.
EOF
fi

printf "Detailed logs per worker are available in %s\n" "$LOG_DIR"

if (( worker_failures )); then
    printf "Warning: one or more workers exited with a non-zero status. Check worker logs for details.\n" >&2
fi
