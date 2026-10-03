param(
    [string]$Python = "python",
    [string]$StageRoot = "",
    [switch]$Bootstrap
)
$ErrorActionPreference = "Stop"
$projectRoot = Split-Path -Parent $PSScriptRoot
# CMake resolves SUBST aliases to the physical path. Stage both project and
# tools in an ASCII path, without deleting or moving any existing user files.
if (-not $StageRoot) { $StageRoot = Join-Path $env:TEMP 'wt32-link-build' }
$stageRoot = [IO.Path]::GetFullPath($StageRoot)
if ($stageRoot -match '[^\x00-\x7F]|\s') { throw "TEMP must have an ASCII path without spaces." }
New-Item -ItemType Directory -Force $stageRoot | Out-Null
foreach ($folder in @('main','components')) {
    & robocopy.exe (Join-Path $projectRoot $folder) (Join-Path $stageRoot $folder) /E /R:1 /W:1 /NFL /NDL /NJH /NJS /NP
    if ($LASTEXITCODE -ge 8) { throw "Copy failed: $folder" }
}
foreach ($name in @('platformio.ini','CMakeLists.txt','partitions.csv','sdkconfig.defaults')) {
    Copy-Item -LiteralPath (Join-Path $projectRoot $name) -Destination $stageRoot -Force
}
$defaultsHash = (Get-FileHash -LiteralPath (Join-Path $projectRoot 'sdkconfig.defaults') -Algorithm SHA256).Hash
$hashFile = Join-Path $stageRoot '.defaults.sha256'
if (-not (Test-Path $hashFile) -or (Get-Content -LiteralPath $hashFile -Raw).Trim() -ne $defaultsHash) {
    # A new defaults file must invalidate CMake, even when the source archive
    # carries older timestamps. Keep IDF's expanded config on unchanged builds.
    [IO.File]::WriteAllText((Join-Path $stageRoot 'sdkconfig.wt32-eth01'), [IO.File]::ReadAllText((Join-Path $projectRoot 'sdkconfig.defaults')), [Text.UTF8Encoding]::new($false))
    Set-Content -LiteralPath $hashFile -Value $defaultsHash -Encoding ascii
}
if (Test-Path (Join-Path $projectRoot '.tools')) {
    & robocopy.exe (Join-Path $projectRoot '.tools') (Join-Path $stageRoot '.tools') /E /R:1 /W:1 /NFL /NDL /NJH /NJS /NP /XD .cache
    if ($LASTEXITCODE -ge 8) { throw "Toolchain copy failed." }
}
$oldPythonPath = $env:PYTHONPATH
$oldCore = $env:PLATFORMIO_CORE_DIR
$oldEncoding = $env:PYTHONIOENCODING
$oldUtf8 = $env:PYTHONUTF8
$oldLocation = Get-Location
try {
    Set-Location $stageRoot
    $env:PYTHONPATH = Join-Path $stageRoot '.tools/python'
    $env:PLATFORMIO_CORE_DIR = Join-Path $stageRoot '.tools/platformio'
    $env:PYTHONIOENCODING = "utf-8"
    $env:PYTHONUTF8 = "1"
    if ($Bootstrap -or -not (Test-Path '.tools/python/platformio')) {
        & $Python -m pip install --target .tools/python 'platformio==6.2.0'
        if ($LASTEXITCODE -ne 0) { throw "PlatformIO installation failed." }
    }
    if (-not (Test-Path '.tools/python/esptool')) {
        & $Python -m pip install --target .tools/python 'esptool==4.5.1'
        if ($LASTEXITCODE -ne 0) { throw "esptool installation failed." }
    }
    if (-not (Test-Path '.tools/build-python/Scripts/python.exe')) {
        & $Python -m venv .tools/build-python
        if ($LASTEXITCODE -ne 0) { throw "Build Python environment creation failed." }
    }
    # PlatformIO's IDF builder clears PYTHONPATH. Use a local venv + .pth so
    # esptool still sees pyserial and its other dependencies in subprocesses.
    Set-Content -LiteralPath '.tools/build-python/Lib/site-packages/wt32_deps.pth' -Value (Join-Path $stageRoot '.tools/python') -Encoding ascii
    $buildPython = Join-Path $stageRoot '.tools/build-python/Scripts/python.exe'
    & $buildPython -m platformio run --silent
    if ($LASTEXITCODE -ne 0) { throw "Firmware build failed." }
    $destination = Join-Path $projectRoot 'release'
    New-Item -ItemType Directory -Force $destination | Out-Null
    foreach ($name in @('firmware.bin','bootloader.bin','partitions.bin','firmware.elf')) {
        Copy-Item -LiteralPath (Join-Path $stageRoot ".pio/build/wt32-eth01/$name") -Destination $destination -Force
    }
    Copy-Item -LiteralPath (Join-Path $stageRoot 'sdkconfig.wt32-eth01') -Destination (Join-Path $destination 'sdkconfig') -Force
    & $Python (Join-Path $projectRoot 'tools/package_release.py') $projectRoot
    if ($LASTEXITCODE -ne 0) { throw "Release packaging failed." }
    Write-Output "Build complete: $destination"
} finally {
    Set-Location $oldLocation
    $env:PYTHONPATH = $oldPythonPath
    $env:PLATFORMIO_CORE_DIR = $oldCore
    $env:PYTHONIOENCODING = $oldEncoding
    $env:PYTHONUTF8 = $oldUtf8
}
