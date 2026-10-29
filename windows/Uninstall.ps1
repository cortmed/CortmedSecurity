#Requires -Version 5.1
# Cortmed Security - Windows kaldirma. Karantina klasoru silinmeden once sorulur.
$dest = Join-Path $env:LOCALAPPDATA 'CortmedSecurity'

# Calisan Cortmed sureclerini kapat ve gercekten kapanmalarini bekle (yoksa dosyalari kilitli kalir)
$procs = @(Get-Process CortmedSecurity -ErrorAction SilentlyContinue) +
    @(Get-CimInstance Win32_Process -Filter "Name='powershell.exe'" |
        Where-Object { $_.CommandLine -match 'CortmedSecurity\.ps1' -and $_.ProcessId -ne $PID } |
        ForEach-Object { Get-Process -Id $_.ProcessId -ErrorAction SilentlyContinue })
foreach ($p in $procs | Where-Object { $_ }) {
    Stop-Process -Id $p.Id -Force -ErrorAction SilentlyContinue
    Wait-Process -Id $p.Id -Timeout 15 -ErrorAction SilentlyContinue
}

# Davranis bekcisi: yalnizca Program Files'taki (kullanicinin yazamadigi) kopya yonetici olarak calistirilir
# Ortam degiskeni yerine: 64 bit islemde [Environment], 32 bit islemde kayit defterindeki 64 bit Program Files
$pfBase = [Environment]::GetFolderPath('ProgramFiles')
if (-not [Environment]::Is64BitProcess) {
    $w6432 = (Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion' -Name ProgramW6432Dir -ErrorAction SilentlyContinue).ProgramW6432Dir
    if ($w6432) { $pfBase = $w6432 }
}
$guardUninstall = Join-Path $pfBase 'Cortmed\Uninstall-Guard.ps1'
if (Test-Path $guardUninstall) {
    # Her zaman 64 bit Windows PowerShell (32 bit kabukta Program Files x86'ya donerdi)
    $ps64 = if ([Environment]::Is64BitOperatingSystem -and -not [Environment]::Is64BitProcess) {
        Join-Path ([Environment]::GetFolderPath('Windows')) 'Sysnative\WindowsPowerShell\v1.0\powershell.exe'
    } else { Join-Path ([Environment]::SystemDirectory) 'WindowsPowerShell\v1.0\powershell.exe' }
    try {
        $gp = Start-Process $ps64 -Verb RunAs -Wait -PassThru -ErrorAction Stop `
            -ArgumentList ('-NoProfile -ExecutionPolicy Bypass -File "{0}"' -f $guardUninstall)
        if ($gp.ExitCode -ne 0) { Write-Host "Davranış bekçisi tam kaldırılamadı (kod $($gp.ExitCode))." -ForegroundColor Yellow }
    } catch {
        Write-Host 'Not: Yönetici izni verilmediği için davranış bekçisi (CortmedGuard hizmeti) kaldırılmadı.' -ForegroundColor Yellow
        Write-Host "Daha sonra yönetici olarak şunu çalıştırabilirsiniz: powershell -ExecutionPolicy Bypass -File ""$guardUninstall"""
    }
}

foreach ($lnk in @(
        (Join-Path ([Environment]::GetFolderPath('Startup')) 'Cortmed Security Bekci.lnk'),
        (Join-Path ([Environment]::GetFolderPath('Desktop')) 'Cortmed Security.lnk'),
        (Join-Path ([Environment]::GetFolderPath('Programs')) 'Cortmed Security.lnk'))) {
    Remove-Item $lnk -Force -ErrorAction SilentlyContinue
}

# Tarayıcı köprüsü kaydı (HKCU): yoksa sessizce geçilir. Köprü dosyaları klasörle birlikte silinir.
foreach ($regPath in 'Software\Google\Chrome\NativeMessagingHosts\com.cortmed.security', 'Software\Microsoft\Edge\NativeMessagingHosts\com.cortmed.security') {
    try { [Microsoft.Win32.Registry]::CurrentUser.DeleteSubKeyTree($regPath, $false) } catch { }
}

$q = Join-Path $dest 'Karantina'
$keepQuarantine = $false
if ((Test-Path $q) -and (Get-ChildItem $q)) {
    $a = Read-Host 'Karantinada dosyalar var (virüslü dosyalar). Onlar da silinsin mi? (E/H)'
    $keepQuarantine = $a -notmatch '^[EeYy]'
}
Set-Location $env:TEMP
if ($keepQuarantine) { Get-ChildItem $dest -Exclude 'Karantina' | Remove-Item -Recurse -Force -ErrorAction SilentlyContinue }
else { Remove-Item $dest -Recurse -Force -ErrorAction SilentlyContinue }

# Silinemeyen dosya kaldiysa basari demeden once soyle
$left = @(Get-ChildItem $dest -Recurse -File -ErrorAction SilentlyContinue | Where-Object { -not $keepQuarantine -or $_.FullName -notlike "$q*" })
if ($left) {
    Write-Host "Bazı dosyalar silinemedi (kullanımda olabilir). Bilgisayarı yeniden başlatıp Kaldir.bat'ı tekrar çalıştırın:" -ForegroundColor Yellow
    $left | Select-Object -First 5 | ForEach-Object { Write-Host "  $($_.FullName)" }
} elseif ($keepQuarantine) {
    Write-Host "Cortmed kaldırıldı. Karantina korundu: $q"
} else {
    Write-Host 'Cortmed Security kaldırıldı.'
}
Write-Host 'Tarayıcınıza eklediğiniz Cortmed eklentisini de kaldırın: chrome://extensions ya da edge://extensions'
Write-Host 'Not: "Tek tıkla aç" ile açılan Windows korumaları açık kalır; geri almak isterseniz kaldırmadan önce Harden.ps1 -Undo çalıştırın.'
