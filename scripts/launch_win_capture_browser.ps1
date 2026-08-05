param(
    [string]$StartUrl = "https://example.com/",
    [switch]$DisableQuic
)

$ErrorActionPreference = "Stop"

$browserCandidates = @(
    "$env:ProgramFiles\Google\Chrome\Application\chrome.exe",
    "${env:ProgramFiles(x86)}\Google\Chrome\Application\chrome.exe",
    "$env:LOCALAPPDATA\Google\Chrome\Application\chrome.exe",
    "$env:ProgramFiles\Microsoft\Edge\Application\msedge.exe",
    "${env:ProgramFiles(x86)}\Microsoft\Edge\Application\msedge.exe"
)

$browser = $browserCandidates |
    Where-Object { Test-Path -LiteralPath $_ } |
    Select-Object -First 1

if (-not $browser) {
    throw "Chrome or Edge was not found."
}

$profile = Join-Path $env:LOCALAPPDATA "ProxyLab\ChromePlainNoProxyProfile"
New-Item -ItemType Directory -Force -Path $profile | Out-Null

Get-CimInstance Win32_Process -Filter "Name = 'chrome.exe' OR Name = 'msedge.exe'" |
    Where-Object { $_.CommandLine -like "*$profile*" } |
    ForEach-Object {
        Stop-Process -Id $_.ProcessId -Force -ErrorAction SilentlyContinue
    }

$browserArgs = @(
    "--user-data-dir=$profile",
    "--no-proxy-server",
    "--disable-background-networking",
    "--disable-background-mode",
    "--disable-component-update",
    "--disable-sync",
    "--no-first-run",
    "--new-window"
)

if ($DisableQuic) {
    $browserArgs += "--disable-quic"
}

if ([string]::IsNullOrWhiteSpace($StartUrl)) {
    $StartUrl = "about:blank"
}
$browserArgs += $StartUrl

$process = Start-Process -FilePath $browser -ArgumentList $browserArgs -PassThru

Write-Host "Capture browser started with NO proxy."
Write-Host "PID: $($process.Id)"
Write-Host "Profile: $profile"
Write-Host "Start URL: $StartUrl"
