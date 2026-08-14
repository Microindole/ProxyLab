#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat <<'EOF'
Usage: scripts/pcap/filter-site.sh [--force] ROOT ALLOWLIST

Recursively find capture.pcap below ROOT. For every capture whose first path
component has entries in ALLOWLIST, create site.pcap in the same directory.
Only entire captured TCP/UDP streams with a visible TLS SNI, HTTP Host, or DNS
query name matching an explicit domain suffix are retained. The original
capture is never modified. A stream may still begin before or end after the
capture boundary.

ALLOWLIST is a tab-separated file:
  site-name<TAB>domain-suffix

Reports written below ROOT:
  domain-audit.tsv       all visible hosts and their occurrence counts
  filter-site-report.tsv per-PCAP retained stream/packet/byte counts

Existing site.pcap files are skipped unless --force is supplied.
EOF
}

force=0
if [[ ${1:-} == --force ]]; then
  force=1
  shift
fi
if (($# != 2)); then
  usage >&2
  exit 2
fi

root=$1
allowlist=$2
[[ -d $root ]] || { echo "error: data root does not exist: $root" >&2; exit 1; }
[[ -s $allowlist ]] || { echo "error: allowlist does not exist or is empty: $allowlist" >&2; exit 1; }
root="$(cd -- "$root" && pwd -P)"
allowlist="$(cd -- "$(dirname -- "$allowlist")" && pwd -P)/$(basename -- "$allowlist")"

for command_name in tshark capinfos find sort awk wc sha256sum; do
  command -v "$command_name" >/dev/null 2>&1 || {
    echo "error: required command not found: $command_name" >&2
    exit 1
  }
done

if ! awk -F '\t' '
  /^[[:space:]]*#/ || /^[[:space:]]*$/ { next }
  NF != 2 || $1 !~ /^[a-zA-Z0-9_-]+$/ ||
      $2 !~ /^[a-zA-Z0-9.-]+$/ { bad=1 }
  END { exit bad }
' "$allowlist"; then
  echo "error: malformed allowlist; expected site<TAB>domain-suffix" >&2
  exit 1
fi

audit_tmp="$root/domain-audit.tsv.tmp.$$"
report_tmp="$root/filter-site-report.tsv.tmp.$$"
trap 'rm -f -- "$audit_tmp" "$report_tmp"' EXIT
printf 'site\thost\tvisible_streams\n' >"$audit_tmp"
printf 'source\toutput\tstatus\tmatched_tcp_streams\tmatched_udp_streams\tpackets\tbytes\tsha256\n' >"$report_tmp"

captures=0
created=0
skipped=0

while IFS= read -r -d '' input; do
  relative=${input#"$root"/}
  site=${relative%%/*}
  if ! awk -F '\t' -v site="$site" '
      $0 !~ /^[[:space:]]*#/ && $1 == site { found=1 }
      END { exit !found }
    ' "$allowlist"; then
    echo "warning: no allowlist entries for site '$site'; skipped $relative" >&2
    continue
  fi

  ((captures += 1))
  session_dir=${input%/*}
  output="$session_dir/site.pcap"
  streams="$session_dir/site-streams.tsv"
  stream_tmp="${streams}.tmp.$$"
  output_tmp="${output}.tmp.$$"
  host_tmp="$session_dir/.site-hosts.tmp.$$"
  rm -f -- "$stream_tmp" "$output_tmp" "$host_tmp"

  # One record identifies the stream and any visible authority. Repeated and
  # comma-separated field values are normalized by the AWK stage below.
  tshark -r "$input" \
    -Y 'tls.handshake.extensions_server_name || http.host || dns.qry.name' \
    -T fields -E separator=$'\t' -E occurrence=a \
    -e tcp.stream -e udp.stream \
    -e tls.handshake.extensions_server_name -e http.host -e dns.qry.name \
    2>/dev/null |
    awk -F '\t' -v OFS='\t' '
      {
        stream_type = $1 != "" ? "tcp" : ($2 != "" ? "udp" : "")
        stream_id = $1 != "" ? $1 : $2
        if (stream_type == "") next
        for (field = 3; field <= 5; field++) {
          count = split($field, hosts, /,/)
          for (item = 1; item <= count; item++) {
            host = tolower(hosts[item])
            sub(/^\*\./, "", host)
            sub(/:[0-9]+$/, "", host)
            sub(/\.$/, "", host)
            if (host != "") print stream_type, stream_id, host
          }
        }
      }
    ' | sort -u >"$host_tmp"

  awk -F '\t' -v OFS='\t' -v site="$site" '
    NR == FNR {
      if ($0 !~ /^[[:space:]]*#/ && $1 == site) {
        suffix_count++
        suffix[suffix_count] = tolower($2)
      }
      next
    }
    {
      host = $3
      for (item = 1; item <= suffix_count; item++) {
        value = suffix[item]
        if (host == value ||
            (length(host) > length(value) &&
             substr(host, length(host) - length(value), 1) == "." &&
             substr(host, length(host) - length(value) + 1) == value)) {
          print $1, $2, host
          break
        }
      }
    }
  ' "$allowlist" "$host_tmp" | sort -u >"$stream_tmp"

  awk -F '\t' -v OFS='\t' -v site="$site" '{ count[$3]++ }
    END { for (host in count) print site, host, count[host] }
  ' "$host_tmp" >>"$audit_tmp"

  tcp_ids=$(awk -F '\t' '$1 == "tcp" { print $2 }' "$stream_tmp" | sort -nu | paste -sd, -)
  udp_ids=$(awk -F '\t' '$1 == "udp" { print $2 }' "$stream_tmp" | sort -nu | paste -sd, -)
  tcp_count=$(awk -F '\t' '$1 == "tcp" { seen[$2]=1 } END { print length(seen) }' "$stream_tmp")
  udp_count=$(awk -F '\t' '$1 == "udp" { seen[$2]=1 } END { print length(seen) }' "$stream_tmp")

  if [[ -e $output && $force -eq 0 ]]; then
    status=skipped
    ((skipped += 1))
  else
    clauses=()
    [[ -n $tcp_ids ]] && clauses+=("tcp.stream in {$tcp_ids}")
    [[ -n $udp_ids ]] && clauses+=("udp.stream in {$udp_ids}")
    if ((${#clauses[@]} == 0)); then
      echo "error: no streams matched '$site' allowlist in $input" >&2
      rm -f -- "$stream_tmp" "$output_tmp" "$host_tmp"
      exit 1
    fi
    display_filter=${clauses[0]}
    if ((${#clauses[@]} == 2)); then
      display_filter="(${clauses[0]} || ${clauses[1]})"
    fi
    tshark -r "$input" -Y "$display_filter" -F pcap -w "$output_tmp" 2>/dev/null
    capinfos "$output_tmp" >/dev/null
    mv -f -- "$output_tmp" "$output"
    mv -f -- "$stream_tmp" "$streams"
    status=created
    ((created += 1))
  fi
  rm -f -- "$stream_tmp" "$output_tmp" "$host_tmp"

  packets=$(tshark -r "$output" -T fields -e frame.number 2>/dev/null | wc -l)
  bytes=$(stat -c %s "$output")
  digest=$(sha256sum "$output" | awk '{print $1}')
  printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n' \
    "$relative" "${output#"$root"/}" "$status" "$tcp_count" "$udp_count" \
    "$packets" "$bytes" "$digest" >>"$report_tmp"
  printf '%-9s tcp=%-6s udp=%-6s packets=%-10s %s\n' \
    "$site" "$tcp_count" "$udp_count" "$packets" "${output#"$root"/}"
done < <(find "$root" -type f -name capture.pcap -print0 | sort -z)

((captures > 0)) || { echo "error: no eligible capture.pcap files found" >&2; exit 1; }

{
  head -n 1 "$audit_tmp"
  tail -n +2 "$audit_tmp" | sort -t $'\t' -k1,1 -k3,3nr -k2,2
} >"$root/domain-audit.tsv"
mv -f -- "$report_tmp" "$root/filter-site-report.tsv"
rm -f -- "$audit_tmp"
trap - EXIT

echo
echo "Input captures: $captures"
echo "Outputs created: $created"
echo "Outputs skipped: $skipped"
echo "Domain audit: $root/domain-audit.tsv"
echo "Filter report: $root/filter-site-report.tsv"
