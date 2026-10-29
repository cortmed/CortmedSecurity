#Requires -Version 5.1
<#
  Cortmed Security - Windows kurulumu (yonetici yetkisi gerekmez)
    * Dosyalari %LOCALAPPDATA%\CortmedSecurity klasorune kopyalar (ayarlar korunur)
    * CortmedSecurity.exe baslaticisini Windows'un kendi C# derleyicisiyle uretir
    * Bilgisayar acilinca bekciyi sistem tepsisinde baslatir
    * Masaustu ve Baslat menusune "Cortmed Security" kisayolu ekler
#>
$ErrorActionPreference = 'Stop'
$src = Split-Path -Parent $MyInvocation.MyCommand.Path
$dest = Join-Path $env:LOCALAPPDATA 'CortmedSecurity'

Write-Host ''
Write-Host '  CORTMED SECURITY kuruluyor...' -ForegroundColor Cyan

$db = @((Join-Path $src 'windows.cmdb'), (Join-Path $src '..\engine\dist\windows.cmdb')) |
    Where-Object { Test-Path $_ } | Select-Object -First 1
if (-not $db) { throw 'windows.cmdb bulunamadi (kurulum klasorunde veya engine\dist altinda olmali)' }

# Calisan bekciyi ve acik paneli kapat ki dosyalar guncellenebilsin
$running = @(Get-Process CortmedSecurity -ErrorAction SilentlyContinue) +
    @(Get-CimInstance Win32_Process -Filter "Name='powershell.exe'" |
        Where-Object { $_.CommandLine -match 'CortmedSecurity\.ps1' -and $_.CommandLine -match '-Mode (Watch|Panel)' } |
        ForEach-Object { Get-Process -Id $_.ProcessId -ErrorAction SilentlyContinue })
foreach ($p in $running | Where-Object { $_ }) {
    Stop-Process -Id $p.Id -Force -ErrorAction SilentlyContinue
    Wait-Process -Id $p.Id -Timeout 10 -ErrorAction SilentlyContinue
}

New-Item -ItemType Directory -Force $dest | Out-Null
foreach ($f in 'CortmedSecurity.ps1', 'CortmedEngine.cs', 'Launcher.cs', 'Harden.ps1', 'Uninstall.ps1', 'cortmed.ico', 'cortmed-logo.png') {
    Copy-Item (Join-Path $src $f) $dest -Force
}
Copy-Item $db (Join-Path $dest 'windows.cmdb') -Force

# Icerik tarama motoru: YARA ve derlenmis kurallar (ClamAV istege bagli, Ayarlar'dan kurulur)
$yara = Join-Path $src 'engines\yara\yara64.exe'
if (Test-Path $yara) {
    New-Item -ItemType Directory -Force (Join-Path $dest 'engines\yara') | Out-Null
    Copy-Item $yara (Join-Path $dest 'engines\yara') -Force
}
$yarc = @((Join-Path $src 'windows.yarc'), (Join-Path $src '..\engine\dist\windows.yarc')) | Where-Object { Test-Path $_ } | Select-Object -First 1
if ($yarc) { Copy-Item $yarc (Join-Path $dest 'windows.yarc') -Force }

# Logolu baslatici: Windows'ta hazir gelen .NET C# derleyicisiyle uretilir
$exe = Join-Path $dest 'CortmedSecurity.exe'
$csc = Join-Path ([Runtime.InteropServices.RuntimeEnvironment]::GetRuntimeDirectory()) 'csc.exe'
try {
    $out = & $csc /nologo /target:winexe /optimize+ "/out:$exe" "/win32icon:$(Join-Path $dest 'cortmed.ico')" `
        "/reference:$([psobject].Assembly.Location)" /reference:System.Windows.Forms.dll (Join-Path $dest 'Launcher.cs') 2>&1
    if ($LASTEXITCODE -ne 0) { throw ($out -join ' ') }
} catch {
    Write-Host "  (Baslatici derlenemedi, PowerShell ile calisacak: $($_.Exception.Message))" -ForegroundColor Yellow
    Remove-Item $exe -Force -ErrorAction SilentlyContinue
}

# Eski surumlerden kalan gizli baslaticilar (derleme olmazsa yedek olarak da kullanilir)
$script = Join-Path $dest 'CortmedSecurity.ps1'
foreach ($mode in 'Watch', 'Panel') {
    $vbs = "CreateObject(""WScript.Shell"").Run ""powershell.exe -NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -File """"$script"""" -Mode $mode"", 0, False"
    Set-Content (Join-Path $dest "cortmed-$($mode.ToLower()).vbs") $vbs -Encoding Unicode
}

$shell = New-Object -ComObject WScript.Shell
function New-Shortcut([string]$lnk, [string]$mode, [string]$desc) {
    $s = $shell.CreateShortcut($lnk)
    if (Test-Path $exe) {
        $s.TargetPath = $exe
        $s.Arguments = if ($mode -eq 'Watch') { '--watch' } else { '' }
        $s.IconLocation = "$exe,0"
    } else {
        $s.TargetPath = Join-Path $env:SystemRoot 'System32\wscript.exe'
        $s.Arguments = '"{0}"' -f (Join-Path $dest "cortmed-$($mode.ToLower()).vbs")
        $s.IconLocation = (Join-Path $dest 'cortmed.ico') + ',0'
    }
    $s.WorkingDirectory = $dest
    $s.Description = $desc
    $s.Save()
}
$startup = Join-Path ([Environment]::GetFolderPath('Startup')) 'Cortmed Security Bekci.lnk'
$desktop = Join-Path ([Environment]::GetFolderPath('Desktop')) 'Cortmed Security.lnk'
$programs = Join-Path ([Environment]::GetFolderPath('Programs')) 'Cortmed Security.lnk'
New-Shortcut $startup 'Watch' 'Cortmed Security arka plan korumasi'
New-Shortcut $desktop 'Panel' 'Cortmed Security'
New-Shortcut $programs 'Panel' 'Cortmed Security'

# Kisayollara uygulama kimligi: gorev cubugu ve bildirimlerde Cortmed adi ve logosu
try {
    Add-Type -TypeDefinition (Get-Content (Join-Path $dest 'CortmedEngine.cs') -Raw -Encoding UTF8)
    foreach ($lnk in @($programs, $desktop)) { [Cortmed.AppIdentity]::SetShortcutAppId($lnk) }
} catch { Write-Host "  (Kisayol kimligi ayarlanamadi: $($_.Exception.Message))" }

function Start-Cortmed([string]$mode) {
    if ((Test-Path $exe) -and $mode -eq 'Watch') { Start-Process $exe -ArgumentList '--watch' }
    elseif (Test-Path $exe) { Start-Process $exe }
    else { Start-Process wscript.exe -ArgumentList ('"{0}"' -f (Join-Path $dest "cortmed-$($mode.ToLower()).vbs")) }
}
Start-Cortmed 'Watch'
Write-Host '  [OK] Cortmed Security sağ altta, sistem tepsisinde çalışıyor (her açılışta otomatik başlar)' -ForegroundColor Green
Write-Host '  [OK] Masaüstüne ve Başlat menüsüne "Cortmed Security" kısayolu eklendi' -ForegroundColor Green
Write-Host ''
Write-Host '  İlk tam tarama arka planda birkaç dakika içinde biter.'
Write-Host '  Öneri: panelde "Önerilerimiz" sekmesindeki "Tek tıkla aç" düğmesine basın.'
Write-Host ''
Start-Cortmed 'Panel'
