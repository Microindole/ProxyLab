param(
    [Parameter(Mandatory = $true)]
    [ValidateSet("Enable", "Disable", "Status")]
    [string]$Action
)

$ErrorActionPreference = "Stop"

$StateDir = Join-Path $env:ProgramData "proxy-traffic-lab"
$StatePath = Join-Path $StateDir "chrome-network-isolation.json"
$RuleGroup = "ProxyTrafficLab Chrome Network Isolation"

function Test-IsAdmin {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($identity)
    return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Get-BrowserCandidates {
    $programFilesX86 = [Environment]::GetEnvironmentVariable("ProgramFiles(x86)")
    $candidates = @(
        (Join-Path $env:ProgramFiles "Google\Chrome\Application\chrome.exe"),
        $(if ($programFilesX86) { Join-Path $programFilesX86 "Google\Chrome\Application\chrome.exe" }),
        $(if ($env:LOCALAPPDATA) { Join-Path $env:LOCALAPPDATA "Google\Chrome\Application\chrome.exe" }),
        (Join-Path $env:ProgramFiles "Microsoft\Edge\Application\msedge.exe"),
        $(if ($programFilesX86) { Join-Path $programFilesX86 "Microsoft\Edge\Application\msedge.exe" })
    )
    $candidates |
        Where-Object { -not [string]::IsNullOrWhiteSpace($_) } |
        Where-Object { Test-Path -LiteralPath $_ } |
        Select-Object -Unique
}

function Save-FirewallState {
    New-Item -ItemType Directory -Force -Path $StateDir | Out-Null
    $profiles = Get-NetFirewallProfile |
        Select-Object Name, DefaultOutboundAction
    $state = [ordered]@{
        created_at_utc = (Get-Date).ToUniversalTime().ToString("o")
        profiles = $profiles
    }
    $state | ConvertTo-Json -Depth 5 | Set-Content -Encoding UTF8 -Path $StatePath
}

function Restore-FirewallState {
    if (-not (Test-Path -LiteralPath $StatePath)) {
        Write-Warning "No saved isolation state found at $StatePath; removing lab rules only."
        return
    }
    $state = Get-Content -Raw -Path $StatePath | ConvertFrom-Json
    foreach ($profile in $state.profiles) {
        Set-NetFirewallProfile `
            -Profile $profile.Name `
            -DefaultOutboundAction $profile.DefaultOutboundAction
    }
    Remove-Item -LiteralPath $StatePath -Force
}

function Remove-LabRules {
    Get-NetFirewallRule -Group $RuleGroup -ErrorAction SilentlyContinue |
        Remove-NetFirewallRule
}

function Enable-Isolation {
    if (-not (Test-IsAdmin)) {
        throw "Administrator PowerShell is required to enable Chrome network isolation."
    }

    $browsers = @(Get-BrowserCandidates)
    if ($browsers.Count -eq 0) {
        throw "Chrome or Edge was not found; cannot create browser allow rules."
    }

    if (-not (Test-Path -LiteralPath $StatePath)) {
        Save-FirewallState
    }
    Remove-LabRules

    foreach ($browser in $browsers) {
        $name = Split-Path -Leaf $browser
        New-NetFirewallRule `
            -DisplayName "ProxyTrafficLab allow browser outbound: $name" `
            -Group $RuleGroup `
            -Direction Outbound `
            -Action Allow `
            -Program $browser `
            -Profile Any `
            -Enabled True | Out-Null
    }

    $svchost = Join-Path $env:SystemRoot "System32\svchost.exe"
    foreach ($protocol in @("UDP", "TCP")) {
        New-NetFirewallRule `
            -DisplayName "ProxyTrafficLab allow DNS outbound: $protocol 53" `
            -Group $RuleGroup `
            -Direction Outbound `
            -Action Allow `
            -Program $svchost `
            -Protocol $protocol `
            -RemotePort 53 `
            -Profile Any `
            -Enabled True | Out-Null
    }

    Set-NetFirewallProfile -Profile Domain, Private, Public -DefaultOutboundAction Block

    Write-Host "Chrome network isolation ENABLED."
    Write-Host "Allowed browsers:"
    $browsers | ForEach-Object { Write-Host "  $_" }
    Write-Host "DNS via svchost.exe TCP/UDP 53 is allowed."
    Write-Host "State saved to: $StatePath"
}

function Disable-Isolation {
    if (-not (Test-IsAdmin)) {
        throw "Administrator PowerShell is required to disable Chrome network isolation."
    }
    Remove-LabRules
    Restore-FirewallState
    Write-Host "Chrome network isolation DISABLED."
}

function Show-Status {
    Write-Host "State file: $StatePath"
    if (Test-Path -LiteralPath $StatePath) {
        Write-Host "Saved state exists."
    } else {
        Write-Host "Saved state does not exist."
    }
    Get-NetFirewallProfile |
        Select-Object Name, DefaultOutboundAction |
        Format-Table -AutoSize
    Get-NetFirewallRule -Group $RuleGroup -ErrorAction SilentlyContinue |
        Select-Object DisplayName, Enabled, Direction, Action |
        Format-Table -AutoSize
}

switch ($Action) {
    "Enable" { Enable-Isolation }
    "Disable" { Disable-Isolation }
    "Status" { Show-Status }
}
