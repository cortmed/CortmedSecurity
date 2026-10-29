#Requires -Version 5.1
# Windows dagitim paketini olusturur: dist\CortmedSecurity-Windows.zip
# (Arkadasina bu zip'i gonder; acip Kur.bat'a cift tiklamasi yeterli.)
$ErrorActionPreference = 'Stop'
[Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12
$root = Split-Path -Parent $MyInvocation.MyCommand.Path
$stage = Join-Path $env:TEMP 'CortmedSecurity-Windows'
$out = Join-Path $root 'dist\CortmedSecurity-Windows.zip'

# Resmi YARA 4.5.5 (VirusTotal/yara GitHub surumu); bir kez indirilip onbellekte tutulur
$yaraUrl = 'https://github.com/VirusTotal/yara/releases/download/v4.5.5/yara-4.5.5-2368-win64.zip'
$yaraCache = Join-Path $root 'engine\.cache\yara-4.5.5'
if (-not (Test-Path (Join-Path $yaraCache 'yara64.exe'))) {
    New-Item -ItemType Directory -Force $yaraCache | Out-Null
    $zip = Join-Path $yaraCache 'yara.zip'
    Invoke-WebRequest $yaraUrl -OutFile $zip -UseBasicParsing
    Expand-Archive $zip $yaraCache -Force
    Remove-Item $zip
}
$yarc = Join-Path $root 'engine\dist\windows.yarc'
if (-not (Test-Path $yarc)) { throw 'engine\dist\windows.yarc yok: once "python engine\build_yara.py" calistir' }

Remove-Item $stage -Recurse -Force -ErrorAction SilentlyContinue
New-Item -ItemType Directory -Force $stage, (Join-Path $stage 'engines\yara'), (Join-Path $root 'dist') | Out-Null
foreach ($f in 'CortmedSecurity.ps1', 'CortmedEngine.cs', 'Harden.ps1', 'Install.ps1', 'Uninstall.ps1', 'Kur.bat', 'Kaldir.bat', 'cortmed.ico', 'cortmed-logo.png', 'Launcher.cs') {
    Copy-Item (Join-Path $root "windows\$f") $stage
}
Copy-Item (Join-Path $root 'engine\dist\windows.cmdb') $stage
Copy-Item $yarc $stage
Copy-Item (Join-Path $yaraCache 'yara64.exe') (Join-Path $stage 'engines\yara')

Remove-Item $out -Force -ErrorAction SilentlyContinue
Compress-Archive -Path "$stage\*" -DestinationPath $out
Remove-Item $stage -Recurse -Force
Write-Host "Hazir: $out"
