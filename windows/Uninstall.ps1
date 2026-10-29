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

foreach ($lnk in @(
        (Join-Path ([Environment]::GetFolderPath('Startup')) 'Cortmed Security Bekci.lnk'),
        (Join-Path ([Environment]::GetFolderPath('Desktop')) 'Cortmed Security.lnk'),
        (Join-Path ([Environment]::GetFolderPath('Programs')) 'Cortmed Security.lnk'))) {
    Remove-Item $lnk -Force -ErrorAction SilentlyContinue
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
Write-Host 'Not: "Tek tıkla aç" ile açılan Windows korumaları açık kalır; geri almak isterseniz kaldırmadan önce Harden.ps1 -Undo çalıştırın.'
