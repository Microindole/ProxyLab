[CmdletBinding()]
param(
    [switch]$Check
)

$ErrorActionPreference = "Stop"
$repoRoot = (Resolve-Path (Join-Path $PSScriptRoot "..\..")).Path
$paths = & git -C $repoRoot ls-files --cached --others --exclude-standard
if ($LASTEXITCODE -ne 0) {
    throw "git ls-files failed"
}

$changed = [System.Collections.Generic.List[string]]::new()
foreach ($relativePath in $paths) {
    $path = Join-Path $repoRoot $relativePath
    if (-not (Test-Path -LiteralPath $path -PathType Leaf)) {
        continue
    }

    $bytes = [System.IO.File]::ReadAllBytes($path)
    if ($bytes -contains 0) {
        continue
    }

    $hasCarriageReturn = $bytes -contains 13
    if (-not $hasCarriageReturn) {
        continue
    }

    $changed.Add($relativePath)
    if ($Check) {
        continue
    }

    $normalized = [System.Collections.Generic.List[byte]]::new($bytes.Length)
    for ($index = 0; $index -lt $bytes.Length; $index++) {
        if ($bytes[$index] -eq 13) {
            if ($index + 1 -lt $bytes.Length -and $bytes[$index + 1] -eq 10) {
                continue
            }
            $normalized.Add(10)
            continue
        }
        $normalized.Add($bytes[$index])
    }
    [System.IO.File]::WriteAllBytes($path, $normalized.ToArray())
}

if ($changed.Count -eq 0) {
    Write-Host "All non-ignored text files use LF."
    exit 0
}

if ($Check) {
    $changed | ForEach-Object { Write-Host "Non-LF line ending: $_" -ForegroundColor Red }
    exit 1
}

$changed | ForEach-Object { Write-Host "Normalized: $_" }
