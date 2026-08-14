#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat <<'EOF'
Usage: scripts/pcap/split-ip.sh [--force] [--input-name NAME] ROOT

Recursively find NAME (default: capture.pcap) below ROOT and create beside it:
  v4.pcap  IPv4 unicast TCP/UDP traffic
  v6.pcap  IPv6 unicast TCP/UDP traffic

The input capture.pcap files are never modified. Existing outputs are skipped
unless --force is supplied. A tab-separated summary is written to
ROOT/split-ip-report.tsv.

The cleanup is deliberately conservative: it removes non-TCP/UDP traffic and
loopback, unspecified, link-local, multicast, and broadcast destinations. It
does not filter by domain, application, port, packet size, or flow state.
EOF
}

force=0
input_name=capture.pcap
while (($# > 0)); do
  case $1 in
    --force) force=1; shift ;;
    --input-name)
      (($# >= 2)) || { usage >&2; exit 2; }
      input_name=$2
      shift 2
      ;;
    --) shift; break ;;
    -*) echo "error: unknown option: $1" >&2; usage >&2; exit 2 ;;
    *) break ;;
  esac
done

if (($# != 1)); then
  usage >&2
  exit 2
fi

root=$1
if [[ $input_name == */* || -z $input_name ]]; then
  echo "error: --input-name must be a plain file name" >&2
  exit 2
fi
if [[ ! -d $root ]]; then
  echo "error: data root does not exist: $root" >&2
  exit 1
fi
root="$(cd -- "$root" && pwd -P)"

for command_name in tshark capinfos find sort wc sha256sum awk; do
  command -v "$command_name" >/dev/null 2>&1 || {
    echo "error: required command not found: $command_name" >&2
    exit 1
  }
done

# Keep packets for which Wireshark can identify the transport protocol. KTAG
# independently rejects fragments that do not contain a complete TCP/UDP header.
v4_filter='ip && (ip.proto == 6 || ip.proto == 17) && !(ip.src == 0.0.0.0 || ip.dst == 0.0.0.0 || ip.src == 127.0.0.0/8 || ip.dst == 127.0.0.0/8 || ip.src == 169.254.0.0/16 || ip.dst == 169.254.0.0/16 || ip.src == 224.0.0.0/4 || ip.dst == 224.0.0.0/4 || ip.dst == 255.255.255.255)'
v6_filter='ipv6 && (tcp || udp) && !(ipv6.src == :: || ipv6.dst == :: || ipv6.src == ::1 || ipv6.dst == ::1 || ipv6.src == fe80::/10 || ipv6.dst == fe80::/10 || ipv6.src == ff00::/8 || ipv6.dst == ff00::/8)'

packet_count() {
  local input=$1
  tshark -r "$input" -T fields -e frame.number 2>/dev/null | wc -l
}

conversation_count() {
  local input=$1
  {
    tshark -r "$input" -Y tcp -T fields -e tcp.stream 2>/dev/null
    tshark -r "$input" -Y udp -T fields -e udp.stream 2>/dev/null |
      awk 'NF { print "u" $0 }'
  } | awk 'NF' | sort -u | wc -l
}

write_split() {
  local input=$1
  local output=$2
  local display_filter=$3
  local temporary="${output}.tmp.$$"

  rm -f -- "$temporary"
  if ! tshark -r "$input" -Y "$display_filter" -F pcap -w "$temporary" 2>/dev/null; then
    rm -f -- "$temporary"
    echo "error: tshark failed while creating $output" >&2
    return 1
  fi
  if ! capinfos "$temporary" >/dev/null 2>&1; then
    rm -f -- "$temporary"
    echo "error: generated PCAP is unreadable: $output" >&2
    return 1
  fi
  mv -f -- "$temporary" "$output"
}

report="$root/split-ip-report.tsv"
temporary_report="${report}.tmp.$$"
trap 'rm -f -- "$temporary_report"' EXIT
printf 'source\toutput\tstatus\tpackets\tconversations\tbytes\tsha256\n' >"$temporary_report"

capture_count=0
created_count=0
skipped_count=0

while IFS= read -r -d '' input; do
  ((capture_count += 1))
  session_dir=${input%/*}

  for family in v4 v6; do
    output="$session_dir/$family.pcap"
    if [[ -e $output && $force -eq 0 ]]; then
      status=skipped
      ((skipped_count += 1))
    else
      if [[ $family == v4 ]]; then
        write_split "$input" "$output" "$v4_filter"
      else
        write_split "$input" "$output" "$v6_filter"
      fi
      status=created
      ((created_count += 1))
    fi

    packets=$(packet_count "$output")
    conversations=$(conversation_count "$output")
    bytes=$(stat -c %s "$output")
    digest=$(sha256sum "$output" | awk '{print $1}')
    relative_source=${input#"$root"/}
    relative_output=${output#"$root"/}
    printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\n' \
      "$relative_source" "$relative_output" "$status" "$packets" \
      "$conversations" "$bytes" "$digest" >>"$temporary_report"

    printf '%-7s packets=%-10s conversations=%-8s %s\n' \
      "$family" "$packets" "$conversations" "$relative_output"
  done
done < <(find "$root" -type f -name "$input_name" -print0 | sort -z)

if ((capture_count == 0)); then
  echo "error: no $input_name files found below $root" >&2
  exit 1
fi

mv -f -- "$temporary_report" "$report"
trap - EXIT

echo
echo "Input captures: $capture_count"
echo "Outputs created: $created_count"
echo "Outputs skipped: $skipped_count"
echo "Report: $report"
