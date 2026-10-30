# Yanlis alarm denemesi: YALNIZCA Windows Sandbox icinde. Cortmed kurulur, sonra Chrome, Discord ve Steam resmi
# kurulumlari sessizce calistirilir; bekcinin bunlar icin dondurma ya da supheli davranis kaydi yazmamasi beklenir.
$ErrorActionPreference = 'Continue'
$desk = [Environment]::GetFolderPath('Desktop')
$kit = Join-Path $desk 'Cortmed'
$res = Join-Path $desk 'Results'
if ($env:USERNAME -ne 'WDAGUtilityAccount') { exit 1 }
New-Item -ItemType Directory -Force $res | Out-Null
Start-Transcript (Join-Path $res 'fa-transcript.txt') -Force | Out-Null
function Step([string]$name, [bool]$ok, [string]$detail = '') {
    Add-Content (Join-Path $res 'fa-results.tsv') ("{0}`t{1}`t{2}" -f $name, $(if ($ok) { 'OK' } else { 'FAIL' }), ($detail -replace '[\r\n\t]+', ' ')) -Encoding UTF8
}
try {
    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
    $pkg = Join-Path $desk 'pkg'
    Add-Type -AssemblyName System.IO.Compression.FileSystem
    [IO.Compression.ZipFile]::ExtractToDirectory((Join-Path $kit 'CortmedSecurity-Windows.zip'), $pkg)
    $inst = Start-Process powershell.exe -ArgumentList '-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', (Join-Path $pkg 'Install.ps1') -PassThru
    [void]$inst.WaitForExit(900000)
    Start-Sleep 10
    Step 'Cortmed kuruldu' ((Get-Service CortmedGuard -ErrorAction SilentlyContinue).Status -eq 'Running') ''
    Start-Sleep 20
    $dl = Join-Path $env:USERPROFILE 'Downloads'
    New-Item -ItemType Directory -Force $dl | Out-Null
    $apps = @(
        @{ n = 'Chrome'; u = 'https://dl.google.com/dl/chrome/install/googlechromestandaloneenterprise64.msi'; f = 'chrome.msi'; a = 'msi'; w = 400 },
        @{ n = 'Discord'; u = 'https://discord.com/api/downloads/distributions/app/installers/latest?channel=stable&platform=win&arch=x64'; f = 'DiscordSetup.exe'; a = '-s'; w = 240 },
        @{ n = 'Steam'; u = 'https://cdn.akamai.steamstatic.com/client/installer/SteamSetup.exe'; f = 'SteamSetup.exe'; a = '/S'; w = 240 }
    )
    foreach ($a in $apps) {
        $file = Join-Path $dl $a.f
        try {
            Invoke-WebRequest $a.u -OutFile $file -UseBasicParsing -TimeoutSec 300
            $p = if ($a.a -eq 'msi') { Start-Process msiexec.exe -ArgumentList '/i', "`"$file`"", '/qn' -PassThru } else { Start-Process $file -ArgumentList $a.a -PassThru }
            [void]$p.WaitForExit($a.w * 1000)
            Start-Sleep 60   # kurulumun ardindan acilan guncelleyiciler ve ilk calisma
            Step "$($a.n) indirildi ve kuruldu" $true ''
        } catch { Step "$($a.n) indirildi ve kuruldu" $false "$_" }
    }
    Start-Sleep 30
    $log = Get-Content 'C:\ProgramData\Cortmed\guard.log' -Encoding UTF8 -ErrorAction SilentlyContinue
    $log | Set-Content (Join-Path $res 'fa-guard-log.txt') -Encoding UTF8
    $freezes = @($log | Where-Object { $_ -match 'donduruldu' })
    $warns = @($log | Where-Object { $_ -match 'Şüpheli davranış' })
    Step 'yanlis alarm: dondurma yok' ($freezes.Count -eq 0) ($freezes -join ' | ')
    Step 'yanlis alarm: supheli davranis kaydi yok' ($warns.Count -eq 0) ($warns -join ' | ')
    $cpu = (Get-Process CortmedGuard -ErrorAction SilentlyContinue)
    if ($cpu) { Step 'CortmedGuard bellek < 80 MB' ($cpu.WorkingSet64 -lt 80MB) ("{0:N0} MB" -f ($cpu.WorkingSet64 / 1MB)) }
} catch { Step 'betik hatasi' $false "$_" }
finally {
    Stop-Transcript | Out-Null
    Set-Content (Join-Path $res 'fa-done.txt') (Get-Date -Format o)
}
