#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat <<'EOF'
Usage: scripts/audit_pcap_summary.sh PCAP [PCAP ...]

Print a compact audit for one or more PCAP files:
  - packets, file size, capture duration
  - IPv4/IPv6 packet share
  - TCP flow count from SYN packets
  - UDP conversation count by 5-tuple
  - common TLS SNI and DNS names when visible

This script is read-only. It never modifies input PCAPs.
EOF
}

if (($# == 0)); then
  usage >&2
  exit 2
fi

for command_name in tshark capinfos awk sort head wc; do
  command -v "$command_name" >/dev/null 2>&1 || {
    echo "error: required command not found: $command_name" >&2
    exit 1
  }
done

count_filter() {
  local input=$1
  local filter=$2
  tshark -r "$input" -Y "$filter" -T fields -e frame.number 2>/dev/null | wc -l
}

for input in "$@"; do
  if [[ ! -s "$input" ]]; then
    echo "error: PCAP does not exist or is empty: $input" >&2
    exit 1
  fi

  echo "== $input =="
  capinfos -c -s -u -a -e "$input"

  total_packets="$(count_filter "$input" "frame")"
  ipv4_packets="$(count_filter "$input" "ip")"
  ipv6_packets="$(count_filter "$input" "ipv6")"
  tcp_flows="$(
    tshark \
      -r "$input" \
      -Y 'tcp.flags.syn == 1 && tcp.flags.ack == 0' \
      -T fields \
      -e ip.src \
      -e ipv6.src \
      -e tcp.srcport \
      -e ip.dst \
      -e ipv6.dst \
      -e tcp.dstport \
      -e tcp.seq_raw \
      2>/dev/null |
      sort -u |
      wc -l
  )"
  udp_conversations="$(
    tshark \
      -r "$input" \
      -Y 'udp' \
      -T fields \
      -e ip.src \
      -e ipv6.src \
      -e udp.srcport \
      -e ip.dst \
      -e ipv6.dst \
      -e udp.dstport \
      2>/dev/null |
      awk -F'\t' 'NF >= 6 { print }' |
      sort -u |
      wc -l
  )"
  udp_443_conversations="$(
    tshark \
      -r "$input" \
      -Y 'udp.port == 443' \
      -T fields \
      -e ip.src \
      -e ipv6.src \
      -e udp.srcport \
      -e ip.dst \
      -e ipv6.dst \
      -e udp.dstport \
      2>/dev/null |
      awk -F'\t' 'NF >= 6 { print }' |
      sort -u |
      wc -l
  )"

  echo "packet_family_total=$total_packets"
  echo "ipv4_packets=$ipv4_packets"
  echo "ipv6_packets=$ipv6_packets"
  echo "tcp_syn_flows=$tcp_flows"
  echo "udp_conversations=$udp_conversations"
  echo "udp_443_conversations=$udp_443_conversations"

  echo "top_tls_sni:"
  tshark \
    -r "$input" \
    -Y 'tls.handshake.extensions_server_name' \
    -T fields \
    -e tls.handshake.extensions_server_name \
    2>/dev/null |
    awk 'NF { count[$0]++ } END { for (name in count) print count[name], name }' |
    sort -nr |
    head -n 12

  echo "top_dns_names:"
  tshark \
    -r "$input" \
    -Y 'dns.qry.name' \
    -T fields \
    -e dns.qry.name \
    2>/dev/null |
    awk 'NF { count[$0]++ } END { for (name in count) print count[name], name }' |
    sort -nr |
    head -n 12

  echo
done
