# Cortmed davranis bekcisi deneme programini derler. Pakete ve zip'e GIRMEZ.
# Cikti: %LOCALAPPDATA%\CortmedBuild\test\CortmedBehaviorTest.exe (OneDrive disinda)
# Bu betik programi CALISTIRMAZ.
param([string]$OutDir)
$ErrorActionPreference = 'Stop'
if (-not $OutDir) { $OutDir = Join-Path $env:LOCALAPPDATA 'CortmedBuild\test' }
New-Item -ItemType Directory -Force $OutDir | Out-Null
$csc = Join-Path ([Runtime.InteropServices.RuntimeEnvironment]::GetRuntimeDirectory()) 'csc.exe'
$src = Join-Path $PSScriptRoot 'CortmedBehaviorTest.cs'
$exe = Join-Path $OutDir 'CortmedBehaviorTest.exe'
& $csc /nologo /target:exe /platform:anycpu /optimize+ /codepage:65001 "/out:$exe" /r:System.dll $src
if ($LASTEXITCODE -ne 0) { Write-Host 'Derleme hatası'; exit 1 }
Write-Host "Derlendi: $exe"
exit 0
