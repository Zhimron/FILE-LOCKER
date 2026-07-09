$ErrorActionPreference = "Stop"

$projectRoot = Split-Path -Parent $MyInvocation.MyCommand.Path
$distRoot = Join-Path $projectRoot "dist"
$exePath = Join-Path $distRoot "PythonFileLocker.exe"
$zipPath = Join-Path $distRoot "PythonFileLocker-Windows.zip"
$packageRoot = Join-Path $distRoot "package"
$stagedExePath = Join-Path $packageRoot "PythonFileLocker.exe"

function Invoke-WithRetry {
    param(
        [string]$Description,
        [scriptblock]$Action
    )

    $lastError = $null
    for ($attempt = 1; $attempt -le 10; $attempt++) {
        try {
            & $Action
            return
        } catch {
            $lastError = $_
            Write-Host "$Description failed on attempt $attempt; retrying..."
            Start-Sleep -Milliseconds (500 * $attempt)
        }
    }
    throw $lastError
}

Set-Location $projectRoot

Write-Host "Installing build dependencies..."
py -m pip install -r .\requirements.txt
py -m pip install -r .\requirements-dev.txt

Write-Host "Building standalone app..."
py -m PyInstaller --noconfirm --clean .\PythonFileLocker.spec

if (-not (Test-Path -LiteralPath $exePath)) {
    throw "Build failed. Missing executable: $exePath"
}

if (Test-Path -LiteralPath $zipPath) {
    $resolvedZip = (Resolve-Path -LiteralPath $zipPath).Path
    $resolvedDist = (Resolve-Path -LiteralPath $distRoot).Path
    if (-not $resolvedZip.StartsWith($resolvedDist, [StringComparison]::OrdinalIgnoreCase)) {
        throw "Refusing to remove unexpected file: $resolvedZip"
    }
    Remove-Item -LiteralPath $resolvedZip -Force
}

if (Test-Path -LiteralPath $packageRoot) {
    $resolvedPackage = (Resolve-Path -LiteralPath $packageRoot).Path
    $resolvedDist = (Resolve-Path -LiteralPath $distRoot).Path
    if (-not $resolvedPackage.StartsWith($resolvedDist, [StringComparison]::OrdinalIgnoreCase)) {
        throw "Refusing to remove unexpected directory: $resolvedPackage"
    }
    Remove-Item -LiteralPath $resolvedPackage -Recurse -Force
}

Write-Host "Creating shareable zip..."
New-Item -ItemType Directory -Path $packageRoot | Out-Null
Invoke-WithRetry "Copying executable for packaging" {
    Copy-Item -LiteralPath $exePath -Destination $stagedExePath -Force
}
Invoke-WithRetry "Creating zip package" {
    Compress-Archive -LiteralPath $stagedExePath -DestinationPath $zipPath -Force
}
Remove-Item -LiteralPath $packageRoot -Recurse -Force

Write-Host ""
Write-Host "Done."
Write-Host "App: $exePath"
Write-Host "Share this zip with another Windows system: $zipPath"
