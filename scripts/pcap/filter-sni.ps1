param(
    [Parameter(Mandatory = $true)]
    [string]$InputPcap,

    [Parameter(Mandatory = $true)]
    [string]$OutputPcap,

    # Pipe-separated keywords matched against TLS/QUIC SNI. Keep this broad
    # enough to include CDNs actually used by the target website.
    [string]$SniRegex = "doubao|byte|byted|volc|zijie|snssdk|toutiao|ibytedtos|pstatp|byteimg|bytecdn|coze",

    [string]$TsharkPath = "D:\Wireshark\tshark.exe",

    [string]$EditcapPath = "D:\Wireshark\editcap.exe"
)

$ErrorActionPreference = "Stop"

if (!(Test-Path $InputPcap)) {
    throw "Input PCAP not found: $InputPcap"
}
if (!(Test-Path $TsharkPath)) {
    throw "tshark.exe not found: $TsharkPath"
}
if (!(Test-Path $EditcapPath)) {
    throw "editcap.exe not found: $EditcapPath"
}

$outputDir = Split-Path -Parent $OutputPcap
if ($outputDir -and !(Test-Path $outputDir)) {
    New-Item -ItemType Directory -Path $outputDir | Out-Null
}

Write-Host "Input : $InputPcap"
Write-Host "Output: $OutputPcap"
Write-Host "SNI   : $SniRegex"

$sniTerms = $SniRegex -split "\|" | Where-Object { $_ -ne "" }
if ($sniTerms.Count -eq 0) {
    throw "At least one SNI keyword is required."
}
$sniFilter = "(" + (($sniTerms | ForEach-Object {
    $escaped = $_.Replace("\", "\\").Replace('"', '\"')
    "tls.handshake.extensions_server_name contains `"$escaped`""
}) -join " or ") + ")"

$tcpStreams = & $TsharkPath `
    -r $InputPcap `
    -Y "$sniFilter && tcp" `
    -T fields `
    -e tcp.stream 2>$null |
    Where-Object { $_ -ne "" } |
    Sort-Object -Unique

$udpStreams = & $TsharkPath `
    -r $InputPcap `
    -Y "$sniFilter && udp" `
    -T fields `
    -e udp.stream 2>$null |
    Where-Object { $_ -ne "" } |
    Sort-Object -Unique

$clauses = @()
foreach ($stream in $tcpStreams) {
    $clauses += "tcp.stream == $stream"
}
foreach ($stream in $udpStreams) {
    $clauses += "udp.stream == $stream"
}

if ($clauses.Count -eq 0) {
    throw "No TCP/UDP streams matched SNI regex: $SniRegex"
}

$displayFilter = "(" + ($clauses -join " or ") + ")"
$tempPcap = [System.IO.Path]::GetTempFileName() + ".pcap"

try {
    & $TsharkPath `
        -r $InputPcap `
        -Y $displayFilter `
        -w $tempPcap

    if (!(Test-Path $tempPcap) -or (Get-Item $tempPcap).Length -le 24) {
        throw "Filtered PCAP is empty."
    }

    & $EditcapPath -F pcap $tempPcap $OutputPcap

    $tcpCount = @($tcpStreams).Count
    $udpCount = @($udpStreams).Count
    $size = (Get-Item $OutputPcap).Length
    Write-Host "Matched TCP streams: $tcpCount"
    Write-Host "Matched UDP streams: $udpCount"
    Write-Host "Filtered bytes     : $size"
    Write-Host "Done."
}
finally {
    Remove-Item -LiteralPath $tempPcap -ErrorAction SilentlyContinue
}
