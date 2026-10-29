#Requires -Version 5.1
<#
  Cortmed Security - davranis bekcisi kaldirma (yonetici yetkisi ister)
  Kurulum bu betigi C:\Program Files\Cortmed icine koyar; Uninstall.ps1 yalnizca o kopyayi yukseltir.
    * CortmedGuard hizmetini durdurur ve siler
    * Sysmon'u yalnizca Cortmed kurduysa (guvenilir veri klasorunde sysmon-installed-by-cortmed isareti) kaldirir
    * Program Files\Cortmed ve ProgramData\Cortmed klasorlerini baglantilari izlemeden siler
  Yollar ortam degiskenlerinden degil, [Environment]'tan alinir.
#>
$ErrorActionPreference = 'Continue'
$winDir = [Environment]::GetFolderPath('Windows')
$app = Join-Path ([Environment]::GetFolderPath('ProgramFiles')) 'Cortmed'
$data = Join-Path ([Environment]::GetFolderPath('CommonApplicationData')) 'Cortmed'
$svcName = 'CortmedGuard'
$sc = Join-Path ([Environment]::SystemDirectory) 'sc.exe'

# --- Guvenilir klasor denetimi. AYNI fonksiyon Install-Guard.ps1'de de var (ayri dosya yerine kopya;
#     test ikisinin ayni oldugunu denetler). Degistirirseniz ikisini birlikte degistirin. ---
# Guvenilir: var, baglanti (reparse point) degil, sahibi Administrators veya SYSTEM, DACL korumali
# ve SYSTEM/Administrators disinda hicbir SID'e yazma izni yok.
function Test-TrustedDir([string]$dir) {
    try {
        $di = New-Object IO.DirectoryInfo $dir
        if (-not $di.Exists) { return $false }
        if ($di.Attributes -band [IO.FileAttributes]::ReparsePoint) { return $false }
        $acl = $di.GetAccessControl()
        $okSids = @('S-1-5-18', 'S-1-5-32-544')
        if ($okSids -notcontains $acl.GetOwner([Security.Principal.SecurityIdentifier]).Value) { return $false }
        if (-not $acl.AreAccessRulesProtected) { return $false }
        # Yazma sayilan haklar: veri/ek yazma, oznitelik, silme, izin ve sahiplik degistirme, genel yazma/tum
        $write = [int64]([Security.AccessControl.FileSystemRights]'WriteData, AppendData, WriteExtendedAttributes, WriteAttributes, Delete, DeleteSubdirectoriesAndFiles, ChangePermissions, TakeOwnership') -bor 0x50000000
        foreach ($r in $acl.GetAccessRules($true, $true, [Security.Principal.SecurityIdentifier])) {
            if ($r.AccessControlType -ne [Security.AccessControl.AccessControlType]::Allow) { continue }
            if ($okSids -contains $r.IdentityReference.Value) { continue }
            if (([int64]$r.FileSystemRights -band $write) -ne 0) { return $false }
        }
        return $true
    } catch { return $false }
}

# Baglantilari izlemeden siler: junction/symlink girdisinin kendisi silinir, hedefe hic girilmez.
# Dosyalar (hardlink dahil) yeniden izinlendirilmez, yalnizca silinir (hardlink'te yalnizca bag kopar).
function Remove-TreeSafe([string]$path) {
    $di = New-Object IO.DirectoryInfo $path
    if ($di.Exists) { Remove-EntrySafe $di }
    elseif ((New-Object IO.FileInfo $path).Exists) { [IO.File]::Delete($path) }
}
# $e: listelemeden gelen girdi; oznitelikleri baglantinin kendisine aittir (hedefe bakilmaz)
function Remove-EntrySafe([IO.FileSystemInfo]$e) {
    if ($e -is [IO.DirectoryInfo]) {
        if (-not ($e.Attributes -band [IO.FileAttributes]::ReparsePoint)) {
            foreach ($c in $e.GetFileSystemInfos()) { Remove-EntrySafe $c }
        }
        [IO.Directory]::Delete($e.FullName, $false)
    } else {
        [IO.File]::Delete($e.FullName)
    }
}
# --- /kopya ---

$me = [Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()
if (-not $me.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Host 'Davranış bekçisini kaldırmak için yönetici izni gerekiyor.' -ForegroundColor Yellow
    exit 1
}

# Betik kaldirilacak klasorun icinde; oradan cik
Set-Location $winDir

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

# Sysmon'a yalnizca onu biz kurduysak dokunulur: isaret VE veri klasoru guvenilir (Sysmon kendini %windir% altina kopyalar)
if ((Test-TrustedDir $data) -and (Test-Path -LiteralPath (Join-Path $data 'sysmon-installed-by-cortmed'))) {
    $sm = Join-Path $winDir 'Sysmon64.exe'
    if (Test-Path $sm) {
        & $sm -u | Out-Null
        if ($LASTEXITCODE -eq 0) { Write-Host 'Sysmon kaldırıldı.' }
        else { Write-Host "Sysmon kaldırılamadı (kod $LASTEXITCODE)." -ForegroundColor Yellow }
    }
}

try { Remove-TreeSafe $data } catch { }
try { Remove-TreeSafe $app } catch { }
# Silinemeyen kaldiysa (or. bu betik kullanimdaysa) kisa bir gecikmeyle cmd silsin; rmdir /s baglantilari izlemez
if (Test-Path -LiteralPath $app) {
    Start-Process (Join-Path ([Environment]::SystemDirectory) 'cmd.exe') -WindowStyle Hidden -WorkingDirectory $winDir `
        -ArgumentList ('/c ping -n 4 127.0.0.1 >nul & rmdir /s /q "{0}"' -f $app)
}
if (Test-Path -LiteralPath $data) { Write-Host "Bazı dosyalar silinemedi: $data" -ForegroundColor Yellow }
Write-Host 'Davranış bekçisi kaldırıldı.'
exit 0
