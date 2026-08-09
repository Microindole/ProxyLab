param(
    [Parameter(Mandatory = $true)]
    [ValidateSet("Enable", "Disable", "Recover", "Status", "Watchdog")]
    [string]$Action,
    [int]$OwnerProcessId = 0
)

$ErrorActionPreference = "Stop"

$StateDir = Join-Path $env:ProgramData "proxy-traffic-lab"
$StatePath = Join-Path $StateDir "chrome-network-isolation.json"
$RuleGroup = "ProxyTrafficLab Chrome Network Isolation"
$RecoveryTaskName = "ProxyTrafficLab Network Isolation Recovery"

function Test-IsAdmin {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($identity)
    return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Assert-IsAdmin {
    param([string]$Operation)

    if (-not (Test-IsAdmin)) {
        throw "Administrator PowerShell is required to $Operation Chrome network isolation."
    }
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

function Read-IsolationState {
    if (-not (Test-Path -LiteralPath $StatePath)) {
        return $null
    }
    return Get-Content -Raw -LiteralPath $StatePath | ConvertFrom-Json
}

function Test-ProcessAlive {
    param([int]$ProcessId)

    if ($ProcessId -le 0) {
        return $false
    }
    return $null -ne (Get-Process -Id $ProcessId -ErrorAction SilentlyContinue)
}

function Save-FirewallState {
    param([int]$OwnerId)

    New-Item -ItemType Directory -Force -Path $StateDir | Out-Null
    $profiles = Get-NetFirewallProfile |
        ForEach-Object {
            [ordered]@{
                Name = $_.Name
                DefaultOutboundAction = $_.DefaultOutboundAction.ToString()
            }
        }
    $state = [ordered]@{
        schema_version = 2
        created_at_utc = (Get-Date).ToUniversalTime().ToString("o")
        owner_process_id = $OwnerId
        profiles = $profiles
    }
    $temporaryPath = "$StatePath.$PID.tmp"
    try {
        $state | ConvertTo-Json -Depth 5 | Set-Content -Encoding UTF8 -LiteralPath $temporaryPath
        Move-Item -Force -LiteralPath $temporaryPath -Destination $StatePath
    } finally {
        Remove-Item -LiteralPath $temporaryPath -Force -ErrorAction SilentlyContinue
    }
}

function Restore-FirewallState {
    $state = Read-IsolationState
    if ($null -eq $state) {
        throw "No saved isolation state found at $StatePath."
    }
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

function Remove-RecoveryTask {
    Unregister-ScheduledTask `
        -TaskName $RecoveryTaskName `
        -Confirm:$false `
        -ErrorAction SilentlyContinue
}

function Install-RecoveryTask {
    $escapedStatePath = $StatePath.Replace("'", "''")
    $escapedRuleGroup = $RuleGroup.Replace("'", "''")
    $escapedTaskName = $RecoveryTaskName.Replace("'", "''")
    $recoveryCommand = @"
`$ErrorActionPreference = 'Stop'
`$statePath = '$escapedStatePath'
`$ruleGroup = '$escapedRuleGroup'
`$taskName = '$escapedTaskName'
if (Test-Path -LiteralPath `$statePath) {
    `$state = Get-Content -Raw -LiteralPath `$statePath | ConvertFrom-Json
    foreach (`$profile in `$state.profiles) {
        Set-NetFirewallProfile -Profile `$profile.Name -DefaultOutboundAction `$profile.DefaultOutboundAction
    }
    Remove-Item -LiteralPath `$statePath -Force
    Get-NetFirewallRule -Group `$ruleGroup -ErrorAction SilentlyContinue | Remove-NetFirewallRule
}
Unregister-ScheduledTask -TaskName `$taskName -Confirm:`$false -ErrorAction SilentlyContinue
"@
    $encodedCommand = [Convert]::ToBase64String(
        [Text.Encoding]::Unicode.GetBytes($recoveryCommand)
    )
    $powershell = Join-Path $env:SystemRoot "System32\WindowsPowerShell\v1.0\powershell.exe"
    $taskAction = New-ScheduledTaskAction `
        -Execute $powershell `
        -Argument "-NoProfile -NonInteractive -EncodedCommand $encodedCommand"
    $taskTrigger = New-ScheduledTaskTrigger -AtStartup
    $taskPrincipal = New-ScheduledTaskPrincipal `
        -UserId "SYSTEM" `
        -LogonType ServiceAccount `
        -RunLevel Highest
    $taskSettings = New-ScheduledTaskSettingsSet `
        -AllowStartIfOnBatteries `
        -DontStopIfGoingOnBatteries `
        -StartWhenAvailable `
        -RestartCount 3 `
        -RestartInterval (New-TimeSpan -Minutes 1) `
        -ExecutionTimeLimit (New-TimeSpan -Minutes 5)
    Register-ScheduledTask `
        -TaskName $RecoveryTaskName `
        -Action $taskAction `
        -Trigger $taskTrigger `
        -Principal $taskPrincipal `
        -Settings $taskSettings `
        -Force | Out-Null
}

function Start-IsolationWatchdog {
    param([int]$OwnerId)

    $powershell = Join-Path $env:SystemRoot "System32\WindowsPowerShell\v1.0\powershell.exe"
    $arguments = @(
        "-NoProfile",
        "-NonInteractive",
        "-ExecutionPolicy", "Bypass",
        "-File", "`"$PSCommandPath`"",
        "-Action", "Watchdog",
        "-OwnerProcessId", $OwnerId
    )
    Start-Process `
        -FilePath $powershell `
        -ArgumentList $arguments `
        -WindowStyle Hidden | Out-Null
}

function Disable-Isolation {
    param([switch]$Quiet)

    Assert-IsAdmin -Operation "disable"
    if (-not (Test-Path -LiteralPath $StatePath)) {
        if (-not $Quiet) {
            Write-Warning "No saved isolation state found; no firewall defaults were changed."
        }
        Remove-RecoveryTask
        return
    }

    # Restore the default policy before removing browser allow rules. If restore
    # fails, keep both the state file and allow rules so recovery remains possible.
    Restore-FirewallState
    Remove-LabRules
    Remove-RecoveryTask
    if (-not $Quiet) {
        Write-Host "Chrome network isolation DISABLED."
    }
}

function Enable-Isolation {
    Assert-IsAdmin -Operation "enable"
    if ($OwnerProcessId -le 0) {
        throw "Enable requires -OwnerProcessId so a watchdog can recover after a crash."
    }

    $existingState = Read-IsolationState
    if ($null -ne $existingState) {
        $existingOwner = [int]($existingState.owner_process_id)
        if (Test-ProcessAlive -ProcessId $existingOwner) {
            throw "Chrome network isolation is already owned by process $existingOwner."
        }
        Write-Warning "Recovering stale Chrome network isolation before starting a new capture."
        Disable-Isolation -Quiet
    }

    $browsers = @(Get-BrowserCandidates)
    if ($browsers.Count -eq 0) {
        throw "Chrome or Edge was not found; cannot create browser allow rules."
    }

    Save-FirewallState -OwnerId $OwnerProcessId
    $enableCompleted = $false
    try {
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
        Install-RecoveryTask
        Start-IsolationWatchdog -OwnerId $OwnerProcessId
        $enableCompleted = $true
    } finally {
        if (-not $enableCompleted) {
            try {
                Restore-FirewallState
            } finally {
                Remove-LabRules
                Remove-RecoveryTask
            }
        }
    }

    Write-Host "Chrome network isolation ENABLED."
    Write-Host "Owner process: $OwnerProcessId"
    Write-Host "Crash watchdog and startup recovery task are active."
    Write-Host "Allowed browsers:"
    $browsers | ForEach-Object { Write-Host "  $_" }
    Write-Host "DNS via svchost.exe TCP/UDP 53 is allowed."
    Write-Host "State saved to: $StatePath"
}

function Recover-Isolation {
    Assert-IsAdmin -Operation "recover"
    if (Test-Path -LiteralPath $StatePath) {
        Disable-Isolation -Quiet
        Write-Host "Stale Chrome network isolation RECOVERED."
    } else {
        Remove-RecoveryTask
    }
}

function Watch-IsolationOwner {
    Assert-IsAdmin -Operation "watch"
    if ($OwnerProcessId -le 0) {
        throw "Watchdog requires -OwnerProcessId."
    }

    try {
        $owner = Get-Process -Id $OwnerProcessId -ErrorAction Stop
        $owner.WaitForExit()
    } catch {
        # The owner already exited; recovery below is still required.
    }

    $state = Read-IsolationState
    if ($null -ne $state -and [int]($state.owner_process_id) -eq $OwnerProcessId) {
        Disable-Isolation -Quiet
    }
}

function Show-Status {
    Write-Host "State file: $StatePath"
    $state = Read-IsolationState
    if ($null -ne $state) {
        Write-Host "Saved state exists."
        Write-Host "Owner process: $($state.owner_process_id)"
        Write-Host "Owner alive: $(Test-ProcessAlive -ProcessId ([int]($state.owner_process_id)))"
    } else {
        Write-Host "Saved state does not exist."
    }
    $recoveryTask = Get-ScheduledTask -TaskName $RecoveryTaskName -ErrorAction SilentlyContinue
    Write-Host "Startup recovery task exists: $($null -ne $recoveryTask)"
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
    "Recover" { Recover-Isolation }
    "Status" { Show-Status }
    "Watchdog" { Watch-IsolationOwner }
}
