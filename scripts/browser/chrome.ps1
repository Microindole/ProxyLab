param(
    [string]$Proxy = "socks5://127.0.0.1:10808",
    [string]$StartUrl = "about:blank",
    [switch]$CheckProxy
)

$ErrorActionPreference = "Stop"

$chromeCandidates = @(
    "$env:ProgramFiles\Google\Chrome\Application\chrome.exe",
    "${env:ProgramFiles(x86)}\Google\Chrome\Application\chrome.exe",
    "$env:LOCALAPPDATA\Google\Chrome\Application\chrome.exe"
)
$chrome = $chromeCandidates |
    Where-Object { Test-Path -LiteralPath $_ } |
    Select-Object -First 1

if (-not $chrome) {
    throw "Google Chrome was not found on Windows."
}

if ($CheckProxy) {
    & curl.exe `
        --fail `
        --silent `
        --show-error `
        --socks5-hostname 127.0.0.1:10808 `
        --connect-timeout 10 `
        --max-time 30 `
        --output NUL `
        https://example.com/
    if ($LASTEXITCODE -ne 0) {
        throw "WSL SOCKS5 proxy check failed; do not start a formal capture."
    }
}

$profile = Join-Path $env:LOCALAPPDATA "ProxyLab\ChromeProfile"
New-Item -ItemType Directory -Force -Path $profile | Out-Null

# A closed window can leave background Chrome processes alive. Stop only the
# dedicated capture profile so every launch reapplies the required proxy flags.
Get-CimInstance Win32_Process -Filter "Name = 'chrome.exe'" |
    Where-Object { $_.CommandLine -like "*$profile*" } |
    ForEach-Object {
        Stop-Process -Id $_.ProcessId -Force -ErrorAction SilentlyContinue
    }
Start-Sleep -Seconds 1

$chromeArgs = @(
    "--user-data-dir=$profile",
    "--proxy-server=$Proxy",
    "--disable-quic",
    "--dns-prefetch-disable",
    "--disable-background-networking",
    "--disable-background-mode",
    "--disable-component-update",
    "--disable-sync",
    "--no-first-run",
    "--new-window",
    $StartUrl
)

$process = Start-Process -FilePath $chrome -ArgumentList $chromeArgs -PassThru
Write-Host "Capture Chrome started through $Proxy"
Write-Host "PID: $($process.Id)"
Write-Host "Profile: $profile"
Write-Host "Downloads: $HOME\Downloads"
