#!/usr/bin/env bash

set -euo pipefail

case_id=""
server_ip=""
server_port=24443
duration_seconds=3600
segment_count=5
target_flows=3000
profile_prefix="sample"
output_root="${HOME}/proxy-lab-data"
progress_interval=2

usage() {
  cat <<'EOF'
Usage: timed-series.sh --case CASE --server-ip IP [options]

Run the existing flow-aware tunnel capture once per timed segment. Each segment
keeps the 3000-flow target for accounting, but an external timer closes it after
one hour and immediately starts the next PCAP.

Options:
  --case CASE                 Protocol case id (required)
  --server-ip IP              Proxy server IP (required)
  --server-port PORT          Proxy server port (default: 24443)
  --duration-seconds SECONDS  Duration of each PCAP (default: 3600)
  --count COUNT               Number of PCAPs (default: 5)
  --target-flows FLOWS        Flow acceptance target (default: 3000)
  --profile-prefix PREFIX     Profiles become PREFIX-01... (default: sample)
  --output-root PATH          Data root (default: ~/proxy-lab-data)
  --progress-interval SEC     Existing capture progress interval (default: 2)
  -h, --help                  Show this help
EOF
}

require_value() {
  if [[ $# -lt 2 || -z "${2:-}" ]]; then
    echo "error: $1 requires a value" >&2
    exit 2
  fi
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --case)
      require_value "$@"
      case_id=$2
      shift 2
      ;;
    --server-ip)
      require_value "$@"
      server_ip=$2
      shift 2
      ;;
    --server-port)
      require_value "$@"
      server_port=$2
      shift 2
      ;;
    --duration-seconds)
      require_value "$@"
      duration_seconds=$2
      shift 2
      ;;
    --count)
      require_value "$@"
      segment_count=$2
      shift 2
      ;;
    --target-flows)
      require_value "$@"
      target_flows=$2
      shift 2
      ;;
    --profile-prefix)
      require_value "$@"
      profile_prefix=$2
      shift 2
      ;;
    --output-root)
      require_value "$@"
      output_root=$2
      shift 2
      ;;
    --progress-interval)
      require_value "$@"
      progress_interval=$2
      shift 2
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      echo "error: unknown argument: $1" >&2
      usage >&2
      exit 2
      ;;
  esac
done

if [[ -z "$case_id" || -z "$server_ip" ]]; then
  echo "error: --case and --server-ip are required" >&2
  usage >&2
  exit 2
fi

for value_name in server_port duration_seconds segment_count target_flows; do
  value=${!value_name}
  if [[ ! "$value" =~ ^[1-9][0-9]*$ ]]; then
    echo "error: $value_name must be a positive integer" >&2
    exit 2
  fi
done

for command_name in lab timeout tee sed tail dirname jq mktemp date; do
  if ! command -v "$command_name" >/dev/null 2>&1; then
    echo "error: required command not found: $command_name" >&2
    exit 2
  fi
done

sudo -v || exit 1

echo "Timed capture series"
echo "  case:             $case_id"
echo "  server:           $server_ip:$server_port"
echo "  segments:         $segment_count"
echo "  seconds/segment:  $duration_seconds"
echo "  acceptance flows: $target_flows"
echo "  output root:      $output_root"
echo

for ((index = 1; index <= segment_count; index += 1)); do
  profile=$(printf '%s-%02d' "$profile_prefix" "$index")
  log_path=$(mktemp "${TMPDIR:-/tmp}/proxy-lab-timed-${index}.XXXXXX.log")

  echo "Starting timed segment $index/$segment_count: $profile"
  echo "The timer includes about one second of capture startup overhead."

  segment_started_epoch=$(date +%s)
  set +e
  timeout \
    --foreground \
    --preserve-status \
    --signal=INT \
    --kill-after=60s \
    "${duration_seconds}s" \
    lab capture run \
      --case "$case_id" \
      --server-ip "$server_ip" \
      --server-port "$server_port" \
      --target-flows "$target_flows" \
      --profile "$profile" \
      --output-root "$output_root" \
      --progress-interval "$progress_interval" \
      --idle-seconds 86400 \
      --finish-timeout 86400 \
      2>&1 | tee "$log_path"
  capture_status=${PIPESTATUS[0]}
  set -e
  segment_elapsed_seconds=$(( $(date +%s) - segment_started_epoch ))

  if (( segment_elapsed_seconds + 5 < duration_seconds )); then
    echo "error: segment $profile ended after ${segment_elapsed_seconds}s, before its timer" >&2
    echo "capture log: $log_path" >&2
    exit 1
  fi

  pcap_path=$(sed -n 's/^PCAP: //p' "$log_path" | tail -n 1)
  if [[ -z "$pcap_path" || ! -f "$pcap_path" ]]; then
    echo "error: segment $profile did not produce a PCAP" >&2
    echo "capture log: $log_path" >&2
    exit 1
  fi

  session_dir=$(dirname "$pcap_path")
  metadata_path="$session_dir/capture.json"
  if [[ ! -f "$metadata_path" ]]; then
    echo "error: segment metadata is missing: $metadata_path" >&2
    exit 1
  fi

  metadata_tmp="${metadata_path}.tmp"
  jq \
    --argjson duration "$duration_seconds" \
    --argjson elapsed "$segment_elapsed_seconds" \
    --arg controller "scripts/pcap/timed-series.sh" \
    '.capture.stop_reason = "duration_elapsed"
     | .capture.target_duration_seconds = $duration
     | .capture.controller_elapsed_seconds = $elapsed
     | .capture.timed_controller = $controller' \
    "$metadata_path" > "$metadata_tmp"
  mv "$metadata_tmp" "$metadata_path"

  rm -f "$log_path"

  echo "Completed timed segment $index/$segment_count"
  echo "  session: $session_dir"
  echo "  elapsed: ${segment_elapsed_seconds}s"
  echo "  capture command status: $capture_status"
  echo
done

echo "Timed capture series completed: $segment_count segment(s)."
