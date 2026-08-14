#!/usr/bin/env bash

# Cycle independent Chromium profiles through real web pages so QUIC connection
# pools are periodically rebuilt. This script does not generate packets itself;
# every captured packet still comes from Chromium talking to real sites.

set -Eeuo pipefail

PARALLEL=12
ROUND_SECONDS=60
REST_SECONDS=5
MAX_ROUNDS=0
NETNS="proxy-lab-udp"
CHROME="${HOME}/.cache/ms-playwright/chromium-1234/chrome-linux64/chrome"

usage() {
  cat <<'EOF'
Usage: class02-cycle.sh [options]

Options:
  --parallel N       Independent Chromium profiles per round (default: 12)
  --round-seconds N  Seconds each round stays open (default: 60)
  --rest-seconds N   Pause between rounds (default: 5)
  --max-rounds N     Stop after N rounds; 0 runs until Ctrl+C (default: 0)
  --netns NAME       Network namespace (default: proxy-lab-udp)
  --chrome PATH      Chromium executable
  -h, --help         Show this help
EOF
}

while (($#)); do
  case "$1" in
    --parallel)
      PARALLEL="$2"
      shift 2
      ;;
    --round-seconds)
      ROUND_SECONDS="$2"
      shift 2
      ;;
    --rest-seconds)
      REST_SECONDS="$2"
      shift 2
      ;;
    --max-rounds)
      MAX_ROUNDS="$2"
      shift 2
      ;;
    --netns)
      NETNS="$2"
      shift 2
      ;;
    --chrome)
      CHROME="$2"
      shift 2
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      echo "error: unknown option: $1" >&2
      usage >&2
      exit 2
      ;;
  esac
done

for value in "$PARALLEL" "$ROUND_SECONDS" "$REST_SECONDS" "$MAX_ROUNDS"; do
  [[ "$value" =~ ^[0-9]+$ ]] || {
    echo "error: numeric options must be non-negative integers" >&2
    exit 2
  }
done

((PARALLEL > 0)) || { echo "error: --parallel must be greater than zero" >&2; exit 2; }
((ROUND_SECONDS > 0)) || { echo "error: --round-seconds must be greater than zero" >&2; exit 2; }

[[ -x "$CHROME" ]] || {
  echo "error: Chromium executable not found: $CHROME" >&2
  exit 1
}

sudo -v
sudo ip netns list | grep -qE "^${NETNS}([[:space:]]|$)" || {
  echo "error: network namespace not found: $NETNS" >&2
  exit 1
}

RUN_ID="$(date -u +%Y%m%dT%H%M%SZ)-$$"
RUNTIME_ROOT="/tmp/proxy-lab-class02-cycle-${RUN_ID}"
mkdir -p "$RUNTIME_ROOT"

PIDS=()
PROFILES=()
KEEPALIVE_PID=""

close_round() {
  local profile

  ((${#PROFILES[@]} > 0)) || return 0
  echo "Closing ${#PROFILES[@]} Chromium profiles..."

  for profile in "${PROFILES[@]}"; do
    sudo pkill -TERM -f -- "--user-data-dir=${profile}" 2>/dev/null || true
  done

  sleep 3

  for profile in "${PROFILES[@]}"; do
    sudo pkill -KILL -f -- "--user-data-dir=${profile}" 2>/dev/null || true
  done

  for pid in "${PIDS[@]}"; do
    wait "$pid" 2>/dev/null || true
  done

  PIDS=()
  PROFILES=()
}

cleanup() {
  local status=$?
  trap - INT TERM EXIT
  close_round
  [[ -z "$KEEPALIVE_PID" ]] || kill "$KEEPALIVE_PID" 2>/dev/null || true
  sudo rm -rf -- "$RUNTIME_ROOT"
  exit "$status"
}

trap cleanup INT TERM EXIT

# Keep the sudo credential alive so later rounds never stop at a hidden prompt.
while true; do
  sudo -n true 2>/dev/null || exit
  sleep 45
done &
KEEPALIVE_PID=$!

UID_NUMBER="$(id -u)"
ROUND=0

while ((MAX_ROUNDS == 0 || ROUND < MAX_ROUNDS)); do
  ROUND=$((ROUND + 1))
  ROUND_ROOT="${RUNTIME_ROOT}/round-${ROUND}"
  mkdir -p "$ROUND_ROOT"

  echo
  echo "Round ${ROUND}: launching ${PARALLEL} independent Chromium profiles"
  echo "Each profile opens four real pages; runtime=${ROUND_SECONDS}s"

  for ((index = 0; index < PARALLEL; index++)); do
    profile="${ROUND_ROOT}/profile-${index}"
    log_file="${ROUND_ROOT}/profile-${index}.log"
    bundle=$(((ROUND + index) % 4))

    case "$bundle" in
      0)
        urls=(
          "https://www.bilibili.com/"
          "https://www.bilibili.com/v/popular/all/"
          "https://live.bilibili.com/"
          "https://cloudflare-quic.com/"
        )
        ;;
      1)
        urls=(
          "https://www.bilibili.com/anime/"
          "https://www.bilibili.com/movie/"
          "https://www.bilibili.com/guochuang/"
          "https://search.bilibili.com/all?keyword=纪录片"
        )
        ;;
      2)
        urls=(
          "https://www.douyin.com/"
          "https://www.iqiyi.com/"
          "https://v.qq.com/"
          "https://cloudflare-quic.com/"
        )
        ;;
      *)
        urls=(
          "https://www.bilibili.com/v/douga/"
          "https://www.bilibili.com/v/music/"
          "https://www.bilibili.com/v/technology/"
          "https://www.bilibili.com/v/information/"
        )
        ;;
    esac

    mkdir -p "$profile"
    PROFILES+=("$profile")

    sudo ip netns exec "$NETNS" \
      runuser -u "$USER" -- \
      env \
        DISPLAY="${DISPLAY:-}" \
        WAYLAND_DISPLAY="${WAYLAND_DISPLAY:-}" \
        XDG_RUNTIME_DIR="/run/user/${UID_NUMBER}" \
      "$CHROME" \
        --no-sandbox \
        --no-proxy-server \
        --enable-quic \
        --no-first-run \
        --no-default-browser-check \
        --disable-sync \
        --user-data-dir="$profile" \
        "${urls[@]}" \
        >"$log_file" 2>&1 &

    PIDS+=("$!")
    sleep 0.4
  done

  echo "Round ${ROUND} READY. You may interact with any visible page."
  sleep "$ROUND_SECONDS"
  close_round

  if ((MAX_ROUNDS == 0 || ROUND < MAX_ROUNDS)); then
    echo "Resting ${REST_SECONDS}s before rebuilding all QUIC connection pools..."
    sleep "$REST_SECONDS"
  fi
done

