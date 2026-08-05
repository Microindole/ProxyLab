param(
    [string]$Interface,
    [string]$Output,
    [int]$DurationSeconds = 0,
    [string]$StartUrl = "https://test-ipv6.com/",
    [switch]$ListInterfaces,
    [switch]$StartChrome,
    [switch]$DisableQuic,
    [ValidateSet("ipv6", "mixed")]
    [string]$IpVersion = "mixed"
)

$ErrorActionPreference = "Stop"

function Find-Tool {
    param(
        [string]$Name,
        [string[]]$Candidates
    )

    foreach ($candidate in $Candidates) {
        if (Test-Path -LiteralPath $candidate) {
            return $candidate
        }
    }

    $command = Get-Command $Name -ErrorAction SilentlyContinue | Select-Object -First 1
    if ($command) {
        return $command.Source
    }

    try {
        $where = & "$env:SystemRoot\System32\where.exe" $Name 2>$null |
            Select-Object -First 1
        if ($where -and (Test-Path -LiteralPath $where)) {
            return $where
        }
    } catch {
        # Fall through to the clear installation error below.
    }

    throw "$Name was not found. Install Wireshark with Npcap, then reopen PowerShell."
}

function Find-Chrome {
    $candidates = @(
        "$env:ProgramFiles\Google\Chrome\Application\chrome.exe",
        "${env:ProgramFiles(x86)}\Google\Chrome\Application\chrome.exe",
        "$env:LOCALAPPDATA\Google\Chrome\Application\chrome.exe",
        "$env:ProgramFiles\Microsoft\Edge\Application\msedge.exe",
        "${env:ProgramFiles(x86)}\Microsoft\Edge\Application\msedge.exe"
    )
    foreach ($candidate in $candidates) {
        if (Test-Path -LiteralPath $candidate) {
            return $candidate
        }
    }
    throw "Chrome or Edge was not found."
}

$dumpcap = Find-Tool `
    -Name "dumpcap.exe" `
    -Candidates @(
        "$env:ProgramFiles\Wireshark\dumpcap.exe",
        "${env:ProgramFiles(x86)}\Wireshark\dumpcap.exe",
        "D:\Wireshark\dumpcap.exe"
    )

if ($ListInterfaces) {
    & $dumpcap -D
    exit $LASTEXITCODE
}

if (-not $Interface) {
    throw "Missing -Interface. Run with -ListInterfaces first and choose the active Wi-Fi/Ethernet interface number."
}

if (-not $Output) {
    $root = Join-Path $env:USERPROFILE "Documents\ProxyLab\IPv6Capture"
    New-Item -ItemType Directory -Force -Path $root | Out-Null
    $stamp = (Get-Date).ToUniversalTime().ToString("yyyyMMddTHHmmssZ")
    $Output = Join-Path $root "$stamp.pcap"
}

$outputParent = Split-Path -Parent $Output
if ($outputParent) {
    New-Item -ItemType Directory -Force -Path $outputParent | Out-Null
}

$captureFilter = if ($IpVersion -eq "ipv6") {
    "ip6 and (tcp port 80 or tcp port 443 or udp port 443)"
} else {
    "(ip or ip6) and (tcp port 80 or tcp port 443 or udp port 443)"
}
$dumpcapArgs = @(
    "-F", "pcap",
    "-i", $Interface,
    "-f", $captureFilter,
    "-s", "0",
    "-w", $Output
)

if ($DurationSeconds -gt 0) {
    $dumpcapArgs += @("-a", "duration:$DurationSeconds")
}

$chromeProcess = $null
if ($StartChrome) {
    $chrome = Find-Chrome
    $profile = Join-Path $env:LOCALAPPDATA "ProxyLab\ChromeIPv6NoProxyProfile"
    New-Item -ItemType Directory -Force -Path $profile | Out-Null

    Get-CimInstance Win32_Process -Filter "Name = 'chrome.exe' OR Name = 'msedge.exe'" |
        Where-Object { $_.CommandLine -like "*$profile*" } |
        ForEach-Object {
            Stop-Process -Id $_.ProcessId -Force -ErrorAction SilentlyContinue
        }

    $chromeArgs = @(
        "--user-data-dir=$profile",
        "--no-proxy-server",
        "--disable-background-networking",
        "--disable-background-mode",
        "--disable-component-update",
        "--disable-sync",
        "--no-first-run",
        "--new-window",
        $StartUrl
    )
    if ($DisableQuic) {
        $chromeArgs += "--disable-quic"
    }

    $chromeProcess = Start-Process -FilePath $chrome -ArgumentList $chromeArgs -PassThru
    Write-Host "Chrome/Edge started with NO proxy."
    Write-Host "Browser PID: $($chromeProcess.Id)"
    Write-Host "Profile: $profile"
}

Write-Host "Starting IPv6 capture"
Write-Host "Interface: $Interface"
Write-Host "IP version: $IpVersion"
Write-Host "Filter: $captureFilter"
Write-Host "Output: $Output"

$captureProcess = Start-Process `
    -FilePath $dumpcap `
    -ArgumentList $dumpcapArgs `
    -NoNewWindow `
    -PassThru

if ($DurationSeconds -gt 0) {
    Wait-Process -Id $captureProcess.Id
} else {
    Write-Host "Press Enter here to stop capture after the current browsing workload."
    [void][Console]::ReadLine()
    if (-not $captureProcess.HasExited) {
        Stop-Process -Id $captureProcess.Id -ErrorAction SilentlyContinue
        Start-Sleep -Seconds 1
    }
}

Write-Host "Capture written:"
Write-Host $Output
