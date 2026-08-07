param(
    # 滚动间隔（秒）
    [double]$IntervalSeconds = 3.0,

    # 随机浮动时间（秒）
    [double]$JitterSeconds = 0.8,

    # 运行时间（分钟）
    # 0 = 无限运行
    [int]$DurationMinutes = 0,

    # 滚轮大小
    # 负数向下滚，正数向上滚
    [int]$WheelDelta = -720,

    # 启动等待时间
    [int]$StartDelaySeconds = 5,

    # 滚动多少次后点击一次
    [int]$ScrollsBeforeClick = 10
)


$ErrorActionPreference = "Stop"


# 参数检查
if ($IntervalSeconds -le 0) {
    throw "IntervalSeconds 必须大于0"
}

if ($JitterSeconds -lt 0) {
    throw "JitterSeconds 不能小于0"
}

if ($JitterSeconds -ge $IntervalSeconds) {
    throw "JitterSeconds 必须小于 IntervalSeconds"
}

if ($ScrollsBeforeClick -le 0) {
    throw "ScrollsBeforeClick 必须大于0"
}



# Windows鼠标API
Add-Type -Namespace Win32 -Name MouseAPI -MemberDefinition @"
[System.Runtime.InteropServices.DllImport("user32.dll")]
public static extern void mouse_event(
    uint dwFlags,
    uint dx,
    uint dy,
    int dwData,
    UIntPtr dwExtraInfo);
"@



# 鼠标事件
$WHEEL = 0x0800
$LEFT_DOWN = 0x0002
$LEFT_UP = 0x0004



$random = New-Object System.Random



# 结束时间
if ($DurationMinutes -gt 0) {
    $EndTime = (Get-Date).AddMinutes($DurationMinutes)
}
else {
    $EndTime = $null
}



Write-Host "==============================="
Write-Host "自动滚动点击启动"
Write-Host "==============================="
Write-Host "滚动间隔       : $IntervalSeconds 秒"
Write-Host "随机浮动       : ±$JitterSeconds 秒"
Write-Host "滚动力度       : $WheelDelta"
Write-Host "滚动次数点击   : $ScrollsBeforeClick 次"
Write-Host "运行时间       : $(if($DurationMinutes -eq 0){'无限'}else{"$DurationMinutes 分钟"})"
Write-Host "==============================="

Write-Host ""
Write-Host "$StartDelaySeconds 秒后开始，请切换到目标窗口..."
Write-Host "Ctrl+C 停止"
Write-Host ""



Start-Sleep -Seconds $StartDelaySeconds



$scrollCounter = 0
$totalScroll = 0
$totalClick = 0



while ($true) {


    # 时间结束
    if ($null -ne $EndTime -and (Get-Date) -ge $EndTime) {
        break
    }



    # 滚动
    [Win32.MouseAPI]::mouse_event(
        $WHEEL,
        0,
        0,
        $WheelDelta,
        [UIntPtr]::Zero
    )


    $scrollCounter++
    $totalScroll++


    Write-Host "滚动次数: $scrollCounter / $ScrollsBeforeClick"



    # 点击
    if ($scrollCounter -ge $ScrollsBeforeClick) {


        Start-Sleep -Milliseconds 300


        [Win32.MouseAPI]::mouse_event(
            $LEFT_DOWN,
            0,
            0,
            0,
            [UIntPtr]::Zero
        )


        Start-Sleep -Milliseconds 50


        [Win32.MouseAPI]::mouse_event(
            $LEFT_UP,
            0,
            0,
            0,
            [UIntPtr]::Zero
        )


        $totalClick++

        Write-Host ">>> 左键点击 #$totalClick"


        $scrollCounter = 0
    }



    # 随机等待
    $delay = $IntervalSeconds +
        (($random.NextDouble() * 2 - 1) * $JitterSeconds)


    $delay = [Math]::Max(0.2,$delay)


    Start-Sleep -Milliseconds ([int]($delay * 1000))
}



Write-Host ""
Write-Host "结束"
Write-Host "总滚动: $totalScroll"
Write-Host "总点击: $totalClick"