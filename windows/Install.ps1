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

# Davranis bekcisi kurulum dosyalari: panelden sonra acilabilsin (Install-Guard.ps1 -Source <dest>)
if (Test-Path (Join-Path $src 'guard')) {
    foreach ($d in 'Core', 'Service') {
        $from = Join-Path $src "guard\$d"
        $to = Join-Path $dest "guard\$d"
        if (-not (Test-Path $from)) { continue }
        New-Item -ItemType Directory -Force $to | Out-Null
        # Eski surumden kalan kaynak dosyasi derlemeyi bozmasin
        Remove-Item (Join-Path $to '*.cs') -Force -ErrorAction SilentlyContinue
        Copy-Item (Join-Path $from '*.cs') $to -Force
    }
    $sx = Join-Path $src 'guard\sysmon-cortmed.xml'
    if (Test-Path $sx) { Copy-Item $sx (Join-Path $dest 'guard') -Force }
}
foreach ($f in 'Install-Guard.ps1', 'Uninstall-Guard.ps1') {
    if (Test-Path (Join-Path $src $f)) { Copy-Item (Join-Path $src $f) $dest -Force }
}
$rules = @((Join-Path $src 'behavior_rules.json'), (Join-Path $src '..\engine\rules\behavior_rules.json')) | Where-Object { Test-Path $_ } | Select-Object -First 1
if ($rules) { Copy-Item $rules (Join-Path $dest 'behavior_rules.json') -Force }
$sigDir = @($src, (Join-Path $src '..\engine\dist')) |
    Where-Object { (Test-Path (Join-Path $_ 'manifest.json')) -and (Test-Path (Join-Path $_ 'manifest.sig')) } | Select-Object -First 1
if ($sigDir) { foreach ($f in 'manifest.json', 'manifest.sig') { Copy-Item (Join-Path $sigDir $f) $dest -Force } }

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
    Add-Type -TypeDefinition (Get-Content (Join-Path $dest 'CortmedEngine.cs') -Raw -Encoding UTF8) -ReferencedAssemblies System.Core
    foreach ($lnk in @($programs, $desktop)) { [Cortmed.AppIdentity]::SetShortcutAppId($lnk) }
} catch { Write-Host "  (Kisayol kimligi ayarlanamadi: $($_.Exception.Message))" }

# Davranis bekcisi: yetkili parca (CortmedGuard hizmeti + Sysmon), Windows bir kez yonetici izni ister
$guardSetup = Join-Path $src 'Install-Guard.ps1'
if (Test-Path $guardSetup) {
    Write-Host '  Davranış bekçisi kuruluyor (Windows yönetici izni isteyecek)...'
    try {
        & $guardSetup -Source $src
        if ($LASTEXITCODE -eq 2) { Write-Host '  [!] Davranış bekçisi kuruldu ama Sysmon kurulamadı' -ForegroundColor Yellow }
        elseif ($LASTEXITCODE -ne 0) { throw "kurulum kodu $LASTEXITCODE" }
        else { Write-Host '  [OK] Davranış bekçisi çalışıyor' -ForegroundColor Green }
    } catch {
        # UAC reddi (Win32 1223) ayrintisiz; diger hatalar kisa nedenle
        $cancel = $false
        for ($e = $_.Exception; $e; $e = $e.InnerException) {
            if ($e -is [ComponentModel.Win32Exception] -and $e.NativeErrorCode -eq 1223) { $cancel = $true }
        }
        Write-Host '  Davranış bekçisi kurulmadı; panelden sonra açabilirsiniz' -ForegroundColor Yellow
        if (-not $cancel) { Write-Host "  ($($_.Exception.Message))" }
    }
}

# Tarayıcı koruması: eklenti dosyaları, köprü programı ve Chrome / Edge köprü kaydı (yönetici izni gerekmez).
# Eklentiyi tarayıcıya kullanıcı panelden ekler; burada tarayıcı açılmaz. Hata olursa kurulum devam eder.
try {
    $extSrc = @((Join-Path $src 'browser\extension'), (Join-Path $src '..\browser\extension')) |
        Where-Object { Test-Path (Join-Path $_ 'manifest.json') } | Select-Object -First 1
    $idFile = @((Join-Path $src 'browser\extension-id.txt'), (Join-Path $src '..\browser\extension-id.txt')) |
        Where-Object { Test-Path $_ } | Select-Object -First 1
    $hostDir = @((Join-Path $src 'browser'), $src) |
        Where-Object { (Test-Path (Join-Path $_ 'CortmedBrowserHost.cs')) -and (Test-Path (Join-Path $_ 'NativeHostManifest.ps1')) } | Select-Object -First 1
    if (-not $extSrc -or -not $idFile -or -not $hostDir) { throw 'eklenti dosyaları pakette bulunamadı' }
    . (Join-Path $hostDir 'NativeHostManifest.ps1')

    $extDest = Join-Path $dest 'browser'
    New-Item -ItemType Directory -Force $extDest | Out-Null
    Copy-Item (Join-Path $extSrc '*') $extDest -Recurse -Force

    $hostExe = Join-Path $dest 'CortmedBrowserHost.exe'
    $out = & $csc /nologo /target:exe /optimize+ /codepage:65001 "/out:$hostExe" /reference:System.dll /reference:System.Core.dll `
        /reference:System.Web.Extensions.dll (Join-Path $hostDir 'CortmedBrowserHost.cs') 2>&1
    if ($LASTEXITCODE -ne 0) { throw ($out -join ' ') }

    $extId = (Get-Content $idFile -Raw -Encoding UTF8).Trim()
    $hostJson = Join-Path $dest 'com.cortmed.security.json'
    $manifest = New-NativeHostManifestJson -HostPath $hostExe -ExtensionId $extId -TemplatePath (Join-Path $hostDir 'com.cortmed.security.json.template')
    [IO.File]::WriteAllText($hostJson, $manifest, (New-Object Text.UTF8Encoding($false)))

    foreach ($regPath in 'Software\Google\Chrome\NativeMessagingHosts\com.cortmed.security', 'Software\Microsoft\Edge\NativeMessagingHosts\com.cortmed.security') {
        $key = [Microsoft.Win32.Registry]::CurrentUser.CreateSubKey($regPath)
        try { $key.SetValue('', $hostJson) } finally { $key.Close() }
    }
    Write-Host '  [OK] Tarayıcı koruması hazır; eklentiyi panelden "Nasıl eklenir?" ile tarayıcınıza ekleyin' -ForegroundColor Green
} catch {
    Write-Host "  Tarayıcı koruması hazırlanamadı; Kur.bat dosyasını yeniden çalıştırarak tekrar deneyebilirsiniz ($($_.Exception.Message))" -ForegroundColor Yellow
}

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
