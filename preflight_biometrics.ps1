$ErrorActionPreference = "Stop"

$projectRoot = $PSScriptRoot
$pythonRuntime = "C:\Users\HP\.cache\codex-runtimes\codex-primary-runtime\dependencies\python\python.exe"
$helperDirectory = Join-Path $projectRoot "tools\FutronicCaptureHelper\bin\Release\net8.0\win-x86\publish"
$helper = Join-Path $helperDirectory "FutronicCaptureHelper.dll"
$ftrApi = Join-Path $helperDirectory "FTRAPI.dll"
$ftrScanApi = Join-Path $helperDirectory "ftrScanApi.dll"
$dotnetRoot = Join-Path $projectRoot "tools\dotnet-x86"
$dotnet = Join-Path $dotnetRoot "dotnet.exe"
$yunet = Join-Path $projectRoot "biometric_app\models\face_detection_yunet_2023mar.onnx"
$sface = Join-Path $projectRoot "biometric_app\models\face_recognition_sface_2021dec.onnx"

Write-Host "BioAccess biometric preflight" -ForegroundColor Cyan

foreach ($requiredFile in @($pythonRuntime, $dotnet, $helper, $ftrApi, $ftrScanApi, $yunet, $sface)) {
    if (-not (Test-Path -LiteralPath $requiredFile)) {
        throw "Required file is missing: $requiredFile"
    }
}
Write-Host "[PASS] Python runtime and OpenCV face models are present." -ForegroundColor Green

$env:DOTNET_ROOT_X86 = $dotnetRoot
$env:DOTNET_ROOT = $dotnetRoot
$scannerPath = $helperDirectory
$env:PATH = "$scannerPath;$dotnetRoot;$env:SystemRoot\System32;$env:SystemRoot"
$probeOutput = & $dotnet $helper --sdk-probe 2>&1
if ($LASTEXITCODE -ne 0 -or ($probeOutput -join " ") -notmatch '"success":true') {
    throw "Futronic scanner probe failed: $($probeOutput -join ' ')"
}
Write-Host "[PASS] FS80, official FTRAPI recognition SDK, capture DLL, helper, and bundled runtime are operational." -ForegroundColor Green

$env:PYTHONPATH = "$projectRoot\vendorlibs;$projectRoot"
& $pythonRuntime -m unittest discover -s (Join-Path $projectRoot "tests") -q
if ($LASTEXITCODE -ne 0) {
    throw "Biometric service tests failed."
}
Write-Host "[PASS] Biometric services and role-based access checks passed." -ForegroundColor Green

Write-Host ""
Write-Host "Preflight completed successfully." -ForegroundColor Cyan
Write-Host "Existing version 3 fingerprint records must be re-enrolled once with the official three-scan Futronic flow."
