param(
    # Base delay between scrolls in seconds.
    [double]$IntervalSeconds = 3.0,

    # Random jitter added/subtracted from the base delay.
    [double]$JitterSeconds = 0.8,

    # Total run time. 0 means run until Ctrl+C.
    [int]$DurationMinutes = 0,

    # Negative values scroll down. One wheel notch is usually -120.
    [int]$WheelDelta = -720,

    # Optional warm-up time after starting the script.
    [int]$StartDelaySeconds = 5
)

$ErrorActionPreference = "Stop"

if ($IntervalSeconds -le 0) {
    throw "IntervalSeconds must be positive."
}
if ($JitterSeconds -lt 0) {
    throw "JitterSeconds cannot be negative."
}
if ($JitterSeconds -ge $IntervalSeconds) {
    throw "JitterSeconds must be smaller than IntervalSeconds."
}
if ($DurationMinutes -lt 0) {
    throw "DurationMinutes cannot be negative."
}

Add-Type -Namespace Win32 -Name NativeMethods -MemberDefinition @"
    [System.Runtime.InteropServices.DllImport("user32.dll")]
    public static extern void mouse_event(
        uint dwFlags,
        uint dx,
        uint dy,
        int dwData,
        UIntPtr dwExtraInfo);
"@

$MOUSEEVENTF_WHEEL = 0x0800
$random = [System.Random]::new()
$endAt = if ($DurationMinutes -gt 0) {
    (Get-Date).AddMinutes($DurationMinutes)
} else {
    $null
}

Write-Host "Auto scroll will start in $StartDelaySeconds seconds."
Write-Host "Put Chrome/Douyin in the foreground now. Press Ctrl+C to stop."
if ($StartDelaySeconds -gt 0) {
    Start-Sleep -Seconds $StartDelaySeconds
}

$count = 0
while ($true) {
    if ($null -ne $endAt -and (Get-Date) -ge $endAt) {
        break
    }

    [Win32.NativeMethods]::mouse_event(
        $MOUSEEVENTF_WHEEL,
        0,
        0,
        $WheelDelta,
        [UIntPtr]::Zero)
    $count += 1

    $jitter = ($random.NextDouble() * 2.0 - 1.0) * $JitterSeconds
    $sleepSeconds = [Math]::Max(0.2, $IntervalSeconds + $jitter)
    Write-Host ("scroll #{0}; next in {1:N2}s" -f $count, $sleepSeconds)
    Start-Sleep -Milliseconds ([int]($sleepSeconds * 1000))
}

Write-Host "Auto scroll stopped after $count scrolls."
