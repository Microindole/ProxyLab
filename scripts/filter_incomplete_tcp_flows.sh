#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat <<'EOF'
Usage: scripts/filter_incomplete_tcp_flows.sh PCAP [PCAP ...]

For each classic PCAP, write:
  <name>.incomplete-streams.tsv  audit manifest of excluded tcp.stream values
  <name>.closed-only.pcap        copy without incomplete outer TCP flows

The input PCAP is never modified. Existing outputs are not overwritten.
EOF
}

if (($# == 0)); then
  usage >&2
  exit 2
fi

for command_name in tshark capinfos awk sort; do
  command -v "$command_name" >/dev/null 2>&1 || {
    echo "error: required command not found: $command_name" >&2
    exit 1
  }
done

for input in "$@"; do
  if [[ ! -s "$input" ]]; then
    echo "error: PCAP does not exist or is empty: $input" >&2
    exit 1
  fi

  stem="${input%.*}"
  manifest="${stem}.incomplete-streams.tsv"
  output="${stem}.closed-only.pcap"

  if [[ -e "$manifest" || -e "$output" ]]; then
    echo "error: output already exists for $input" >&2
    echo "       remove or rename it explicitly before rerunning" >&2
    exit 1
  fi

  temporary_manifest="${manifest}.tmp.$$"
  temporary_output="${output}.tmp.$$"
  cleanup() {
    rm -f -- "$temporary_manifest" "$temporary_output"
  }
  trap cleanup EXIT

  printf 'tcp_stream\tpackets\tbytes\torigin\tpeer\tfin_origin\tfin_peer\trst\n' \
    >"$temporary_manifest"

  tshark \
    -r "$input" \
    -T fields \
    -E separator=, \
    -e tcp.stream \
    -e ip.src \
    -e ip.dst \
    -e tcp.srcport \
    -e tcp.dstport \
    -e tcp.flags.syn \
    -e tcp.flags.ack \
    -e tcp.flags.fin \
    -e tcp.flags.reset \
    -e frame.len \
    2>/dev/null |
    awk -F, '
      NF >= 10 && $1 != "" {
        stream = $1
        packets[stream]++
        bytes[stream] += $10
        if ($6 == "True" && $7 == "False") {
          seen[stream] = 1
          origin[stream] = $2 ":" $4
          peer[stream] = $3 ":" $5
        }
        if ($8 == "True") {
          endpoint = $2 ":" $4
          if (endpoint == origin[stream])
            fin_origin[stream] = 1
          else
            fin_peer[stream] = 1
        }
        if ($9 == "True")
          reset[stream] = 1
      }
      END {
        for (stream in seen) {
          if (!reset[stream] && !(fin_origin[stream] && fin_peer[stream])) {
            printf "%s\t%d\t%d\t%s\t%s\t%d\t%d\t%d\n", \
              stream, packets[stream], bytes[stream], origin[stream], peer[stream], \
              fin_origin[stream] + 0, fin_peer[stream] + 0, reset[stream] + 0
          }
        }
      }
    ' |
    sort -n -k1,1 >>"$temporary_manifest"

  incomplete_count="$(awk 'NR > 1 { count++ } END { print count + 0 }' "$temporary_manifest")"

  if ((incomplete_count == 0)); then
    cp --reflink=auto -- "$input" "$temporary_output"
  else
    filter=''
    while IFS=$'\t' read -r stream _; do
      [[ "$stream" == "tcp_stream" ]] && continue
      if [[ -n "$filter" ]]; then
        filter+=" && "
      fi
      filter+="tcp.stream != $stream"
    done <"$temporary_manifest"

    tshark -2 -r "$input" -Y "$filter" -F pcap -w "$temporary_output" 2>/dev/null
  fi

  capinfos -c "$temporary_output" >/dev/null

  original_flows="$(
    tshark -r "$input" \
      -Y 'tcp.flags.syn == 1 && tcp.flags.ack == 0' \
      -T fields -e tcp.stream 2>/dev/null |
      sort -nu |
      wc -l
  )"
  filtered_flows="$(
    tshark -r "$temporary_output" \
      -Y 'tcp.flags.syn == 1 && tcp.flags.ack == 0' \
      -T fields -e tcp.stream 2>/dev/null |
      sort -nu |
      wc -l
  )"

  if ((original_flows - filtered_flows != incomplete_count)); then
    echo "error: flow-count verification failed for $input" >&2
    exit 1
  fi

  mv -- "$temporary_manifest" "$manifest"
  mv -- "$temporary_output" "$output"
  trap - EXIT

  echo "Input:             $input"
  echo "Incomplete flows:  $incomplete_count"
  echo "Original flows:    $original_flows"
  echo "Closed-only flows: $filtered_flows"
  echo "Manifest:          $manifest"
  echo "Filtered PCAP:     $output"
done
