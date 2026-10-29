#Requires -Version 5.1
<#
  Cortmed Security - davranis bekcisi kaldirma (yonetici yetkisi ister)
  Kurulum bu betigi C:\Program Files\Cortmed icine koyar; Uninstall.ps1 yalnizca o kopyayi yukseltir.
    * CortmedGuard hizmetini durdurur ve siler
    * Sysmon'u yalnizca Cortmed kurduysa (sysmon-installed-by-cortmed isareti) kaldirir
    * Program Files\Cortmed ve ProgramData\Cortmed klasorlerini siler
#>
$ErrorActionPreference = 'Continue'
$pfBase = if ($env:ProgramW6432) { $env:ProgramW6432 } else { $env:ProgramFiles }
$app = Join-Path $pfBase 'Cortmed'
$data = Join-Path $env:ProgramData 'Cortmed'
$svcName = 'CortmedGuard'
$sc = Join-Path $env:windir 'System32\sc.exe'

$me = [Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()
if (-not $me.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Host 'Davranış bekçisini kaldırmak için yönetici izni gerekiyor.' -ForegroundColor Yellow
    exit 1
}

# Betik kaldirilacak klasorun icinde; oradan cik
Set-Location $env:windir

$svc = Get-Service $svcName -ErrorAction SilentlyContinue
if ($svc) {
    if ($svc.Status -ne 'Stopped') {
        & $sc stop $svcName | Out-Null
        try { $svc.WaitForStatus('Stopped', [TimeSpan]::FromSeconds(30)) } catch { }
    }
    Get-Process CortmedGuard -ErrorAction SilentlyContinue | Stop-Process -Force -ErrorAction SilentlyContinue
    & $sc delete $svcName | Out-Null
    if ($LASTEXITCODE -eq 0) { Write-Host 'CortmedGuard hizmeti kaldırıldı.' }
    else { Write-Host "CortmedGuard hizmeti silinemedi (kod $LASTEXITCODE)." -ForegroundColor Yellow }
}

# Sysmon'a yalnizca onu biz kurduysak dokunulur (Sysmon kendini %windir% altina kopyalar)
if (Test-Path (Join-Path $data 'sysmon-installed-by-cortmed')) {
    $sm = Join-Path $env:windir 'Sysmon64.exe'
    if (Test-Path $sm) {
        & $sm -u | Out-Null
        if ($LASTEXITCODE -eq 0) { Write-Host 'Sysmon kaldırıldı.' }
        else { Write-Host "Sysmon kaldırılamadı (kod $LASTEXITCODE)." -ForegroundColor Yellow }
    }
}

Remove-Item $data -Recurse -Force -ErrorAction SilentlyContinue
Remove-Item $app -Recurse -Force -ErrorAction SilentlyContinue
# Silinemeyen kaldiysa (or. bu betik kullanimdaysa) kisa bir gecikmeyle cmd silsin
if (Test-Path $app) {
    Start-Process (Join-Path $env:windir 'System32\cmd.exe') -WindowStyle Hidden -WorkingDirectory $env:windir `
        -ArgumentList ('/c ping -n 4 127.0.0.1 >nul & rmdir /s /q "{0}"' -f $app)
}
if (Test-Path $data) { Write-Host "Bazı dosyalar silinemedi: $data" -ForegroundColor Yellow }
Write-Host 'Davranış bekçisi kaldırıldı.'
exit 0
