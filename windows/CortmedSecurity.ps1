#Requires -Version 5.1
<#
  Cortmed Security - Windows

  Modlar:
    Panel     Durum penceresi (varsayilan)
    Watch     Arka plan bekcisi: Indirilenler / Masaustu'ne dusen dosyalari aninda tarar,
              gunde bir tam kontrol ve veritabani guncellemesi yapar
    Daily     Tam kontrol: guvenlik ayarlari, baslangic programlari, Discord, Indirilenler
    Update    Veritabanini guncelle
    ScanFile  Tek dosya tara (-Path)
    Lib       Hicbir sey calistirma (fonksiyonlari test icin yukle)
#>
param(
    [ValidateSet('Panel', 'Watch', 'Daily', 'Update', 'ScanFile', 'InstallClamAV', 'Lib')]
    [string]$Mode = 'Panel',
    [string]$Path
)

$ErrorActionPreference = 'Stop'
[Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12
$Root = Split-Path -Parent $MyInvocation.MyCommand.Path
$DataDir = Join-Path $Root 'data'
$QuarantineDir = Join-Path $Root 'Karantina'
$ConfigPath = Join-Path $Root 'config.json'
$StatusPath = Join-Path $DataDir 'status.json'
$CachePath = Join-Path $DataDir 'filecache.json'
$LogPath = Join-Path $DataDir 'log.txt'
# Davranis bekcisi hizmetinin klasoru (ProgramData\Cortmed): tepsi buradan yalnizca okur, asla yazmaz
$GuardDataDir = Join-Path ([Environment]::GetFolderPath('CommonApplicationData')) 'Cortmed'
New-Item -ItemType Directory -Force $DataDir, $QuarantineDir | Out-Null

$RiskyExtensions = @('.exe', '.scr', '.msi', '.bat', '.cmd', '.ps1', '.vbs', '.vbe', '.js', '.jse', '.wsf',
    '.hta', '.lnk', '.pif', '.com', '.cpl', '.jar', '.zip', '.rar', '.7z', '.iso', '.img', '.dll',
    '.appx', '.msix', '.msixbundle', '.reg', '.url')
$ProgramExtensions = @('.exe', '.scr', '.msi', '.com', '.pif', '.cpl', '.dll')
$SafeDns = @('1.1.1.2', '1.0.0.2', '1.1.1.3', '1.0.0.3', '9.9.9.9', '149.112.112.112',
    '94.140.14.14', '94.140.15.15', '185.228.168.9', '185.228.169.9')

# ------------------------------------------------------------------ temel

function Write-Log([string]$msg) {
    $line = '{0:yyyy-MM-dd HH:mm:ss}  {1}' -f (Get-Date), $msg
    try {
        if ((Test-Path $LogPath) -and (Get-Item $LogPath).Length -gt 2MB) { Move-Item $LogPath "$LogPath.old" -Force }
        Add-Content -Path $LogPath -Value $line -Encoding UTF8
    } catch { }
}

# Her gece GitHub'da derlenen veritabaninin adresi (.github/workflows/update-db.yml)
$DefaultUpdateUrl = 'https://github.com/cortmed/CortmedSecurity/releases/download/db-latest'

function Get-Config {
    $cfg = [ordered]@{
        vtKey      = ''
        # Kullanicinin "bu dosyaya guveniyorum" dedigi dosyalarin SHA-256 parmak izleri
        trustedHashes = @()
        updateUrl  = $DefaultUpdateUrl
        watchDirs  = @()
        # false = sadece uyar, dosyalara asla dokunma (varsayilan)
        autoQuarantine = $false
        # Ucuncu motor: ClamAV (yaklasik 500 MB, varsayilan kapali)
        clamav     = $false
        # true = sari / bilgi bildirimleri gosterilmez; kirmizi (tehlikeli) uyarilar her zaman gosterilir
        quietMode  = $false
    }
    if (Test-Path $ConfigPath) {
        $saved = Get-Content $ConfigPath -Raw -Encoding UTF8 | ConvertFrom-Json
        foreach ($p in $saved.PSObject.Properties) { $cfg[$p.Name] = $p.Value }
    }
    # Bos birakilmis adres resmi Cortmed guncelleme adresine doner
    if (-not ([string]$cfg.updateUrl).Trim()) { $cfg.updateUrl = $DefaultUpdateUrl }
    return [pscustomobject]$cfg
}

function Save-Config($cfg) {
    $cfg | ConvertTo-Json | Set-Content -Path $ConfigPath -Encoding UTF8
}

function Read-Json($file, $default) {
    if (Test-Path $file) {
        try { return Get-Content $file -Raw -Encoding UTF8 | ConvertFrom-Json } catch { }
    }
    return $default
}

function Write-Json($file, $obj) {
    $tmp = "$file.tmp"
    $obj | ConvertTo-Json -Depth 6 | Set-Content -Path $tmp -Encoding UTF8
    Move-Item $tmp $file -Force
}

function New-Finding([string]$key, [string]$level, [string]$title, [string]$detail, [string]$path = '') {
    [pscustomobject]@{ key = $key; level = $level; title = $title; detail = $detail; path = $path }
}

# Panelde hangi sekmede gorunecegi: tehditler (kirmizi ve supheli dosyalar) ya da oneriler
function Get-FindingTab($f) {
    if ($f.level -eq 'RED' -or $f.tab -eq 'threat') { return 'threat' }
    return 'advice'
}

# ------------------------------------------------------------------ motor

function Initialize-EngineType {
    if (-not ('Cortmed.CortmedDb' -as [type])) {
        Add-Type -TypeDefinition (Get-Content (Join-Path $Root 'CortmedEngine.cs') -Raw -Encoding UTF8) -ReferencedAssemblies System.Core
    }
}

# Yeni veritabani daha yeni olmali ve elimizdekinin en az yarisi kadar imza tasimali (yarim derlemeye karsi)
function Test-DbAcceptable($candidate, $current) {
    return $candidate.BuildTime -gt $current.BuildTime -and $candidate.SignatureCount -ge [int]($current.SignatureCount / 2)
}

function Initialize-Engine {
    Initialize-EngineType
    $candidates = @((Join-Path $DataDir 'windows.cmdb'), (Join-Path $Root 'windows.cmdb')) | Where-Object { Test-Path $_ }
    $best = $null
    foreach ($c in $candidates) {
        try {
            $db = [Cortmed.CortmedDb]::Load($c)
            if (-not $best -or (Test-DbAcceptable $db $best)) { $best = $db }
        } catch { Write-Log "Veritabani okunamadi: $c ($_)" }
    }
    if (-not $best) { throw 'Cortmed veritabani (windows.cmdb) bulunamadi' }
    $script:Db = $best
}

# ------------------------------------------------------------------ icerik motorlari

# Dosyanin icerigini tarayan yerel motorlar: Microsoft Defender ve YARA her zaman,
# ClamAV ayarlardan acilirsa. Hicbiri dosyaya dokunmaz; sadece sonuc dondurur.
$EnginesDir = Join-Path $Root 'engines'
$ClamDir = Join-Path $EnginesDir 'clamav'
$ClamStatusPath = Join-Path $DataDir 'clamav-status.txt'
$ClamUrl = 'https://github.com/Cisco-Talos/clamav/releases/download/clamav-1.5.4/clamav-1.5.4.win.x64.zip'
$script:ClamResults = $null

function Invoke-DefenderScan([string]$file) {
    $mp = Join-Path $env:ProgramFiles 'Windows Defender\MpCmdRun.exe'
    if (-not (Test-Path $mp)) { return [pscustomobject]@{ status = 'na'; name = '' } }
    try {
        # -DisableRemediation: Defender sadece rapor eder, dosyaya dokunmaz
        $out = (& $mp -Scan -ScanType 3 -File $file -DisableRemediation 2>&1) | Out-String
        $m = [regex]::Match($out, 'Threat\s*:\s*(.+)')
        if ($m.Success) { return [pscustomobject]@{ status = 'found'; name = $m.Groups[1].Value.Trim() } }
        if ($out -match 'found no threats') { return [pscustomobject]@{ status = 'clean'; name = '' } }
    } catch { }
    return [pscustomobject]@{ status = 'na'; name = '' }
}

function Get-YaraPaths {
    $exe = Join-Path $EnginesDir 'yara\yara64.exe'
    $rules = @((Join-Path $DataDir 'windows.yarc'), (Join-Path $Root 'windows.yarc')) | Where-Object { Test-Path $_ } |
        Sort-Object { (Get-Item $_).LastWriteTimeUtc } -Descending | Select-Object -First 1
    if ((Test-Path $exe) -and $rules) { return @($exe, $rules) }
    return $null
}

# Eslesen kurallar ve puanlari (YARA-Forge kurallari 0-100 arasi "score" tasir)
function Invoke-YaraScan([string]$file) {
    $p = Get-YaraPaths
    if (-not $p) { return @() }
    try {
        $out = & $p[0] -w -m -a 30 -C $p[1] $file 2>$null
        return @(foreach ($line in $out) {
                $m = [regex]::Match([string]$line, '^(\S+)\s+\[(.*)\]\s')
                if ($m.Success) {
                    $score = if ($m.Groups[2].Value -match 'score\s*=\s*(\d+)') { [int]$Matches[1] } else { 60 }
                    [pscustomobject]@{ rule = $m.Groups[1].Value; score = $score }
                }
            })
    } catch { return @() }
}

function Test-ClamReady {
    return ((Get-Config).clamav -eq $true) -and (Test-Path (Join-Path $ClamDir 'clamscan.exe')) -and
        [bool](Get-ChildItem (Join-Path $ClamDir 'db') -Filter '*.c?d' -ErrorAction SilentlyContinue)
}

# Birden cok dosyayi tek seferde tarar (imzalar bir kez yuklenir). Sonuc: yol -> virus adi
function Invoke-ClamScan([string[]]$files) {
    $result = @{}
    if (-not $files -or -not (Test-ClamReady)) { return $result }
    $list = Join-Path $DataDir 'clamav-list.txt'
    [IO.File]::WriteAllLines($list, [string[]]$files)
    try {
        $out = & (Join-Path $ClamDir 'clamscan.exe') "--database=$(Join-Path $ClamDir 'db')" --no-summary --infected --stdout "--file-list=$list" 2>$null
        foreach ($line in $out) {
            $m = [regex]::Match([string]$line, '^(.*): (.+) FOUND$')
            if ($m.Success) { $result[$m.Groups[1].Value] = $m.Groups[2].Value }
        }
    } catch { Write-Log "ClamAV hatasi: $_" }
    return $result
}

function Get-ContentScan([string]$file, [switch]$SkipClam) {
    $clamOn = Test-ClamReady
    $clam = $null
    if ($script:ClamResults -and $script:ClamResults.ContainsKey($file)) { $clam = $script:ClamResults[$file] }
    elseif ($clamOn -and -not $SkipClam -and -not $script:ClamResults) { $clam = (Invoke-ClamScan @($file))[$file] }
    [pscustomobject]@{
        defender  = Invoke-DefenderScan $file
        yara      = Invoke-YaraScan $file
        yaraReady = [bool](Get-YaraPaths)
        clam      = $clam
        clamOn    = $clamOn
        clamRan   = $clamOn -and (-not $SkipClam -or $script:ClamResults)
    }
}

# ClamAV'i resmi GitHub surumunden kurar ve imzalarini indirir (yaklasik 500 MB)
function Install-ClamAV {
    Set-Content $ClamStatusPath 'kuruluyor'
    try {
        New-Item -ItemType Directory -Force $EnginesDir | Out-Null
        if (-not (Test-Path (Join-Path $ClamDir 'clamscan.exe'))) {
            $zip = Join-Path $EnginesDir 'clamav.zip'
            Invoke-WebRequest $ClamUrl -OutFile $zip -UseBasicParsing -TimeoutSec 1800
            $tmp = Join-Path $EnginesDir 'clamav-tmp'
            Remove-Item $tmp -Recurse -Force -ErrorAction SilentlyContinue
            Expand-Archive $zip $tmp -Force
            $inner = Get-ChildItem $tmp -Directory | Select-Object -First 1
            Remove-Item $ClamDir -Recurse -Force -ErrorAction SilentlyContinue
            Move-Item $inner.FullName $ClamDir
            Remove-Item $tmp, $zip -Recurse -Force -ErrorAction SilentlyContinue
        }
        $db = Join-Path $ClamDir 'db'
        New-Item -ItemType Directory -Force $db | Out-Null
        # Zararsiz Cortmed test dosyasi icin imza (sha256:boyut:ad)
        Set-Content (Join-Path $db 'cortmed.hsb') '0095ba2a1b3cecdb0e02aa44c1d5784ed7960d3adf260b6ffcca9db5d0997b6f:52:Cortmed.Test.Dosyasi' -Encoding ASCII
        Set-Content (Join-Path $ClamDir 'freshclam.conf') "DatabaseDirectory $db`r`nDatabaseMirror database.clamav.net`r`n" -Encoding ASCII
        Update-ClamAV
        if (Test-ClamReady) { Set-Content $ClamStatusPath 'hazir'; Write-Log 'ClamAV kuruldu' }
        else { Set-Content $ClamStatusPath 'hata: imzalar indirilemedi' }
    } catch {
        Set-Content $ClamStatusPath "hata: $($_.Exception.Message)"
        Write-Log "ClamAV kurulamadi: $_"
    }
}

function Update-ClamAV {
    $fc = Join-Path $ClamDir 'freshclam.exe'
    if (-not (Test-Path $fc)) { return }
    try {
        $out = & $fc "--config-file=$(Join-Path $ClamDir 'freshclam.conf')" --stdout 2>&1 | Out-String
        Write-Log ('ClamAV imza guncellemesi: ' + (($out -split "`n" | Where-Object { $_ -match 'updated|up-to-date|ERROR' } | Select-Object -First 3) -join ' | '))
    } catch { Write-Log "freshclam hatasi: $_" }
}

function Get-ClamStatusText {
    if ((Get-Config).clamav -ne $true) { return 'Kapalı (Ayarlar''dan açılabilir)' }
    if (Test-ClamReady) { return $null }
    $s = if (Test-Path $ClamStatusPath) { (Get-Content $ClamStatusPath -Raw).Trim() } else { '' }
    if ($s -like 'hata*') { return "Kurulamadı ($s). Düğmeyi kapatıp yeniden açınca tekrar denenir" }
    if (Test-ClamInstalling) { return 'Kuruluyor, birkaç dakika içinde hazır olur' }
    return 'Kurulum yarıda kaldı. Düğmeyi kapatıp yeniden açınca tekrar denenir'
}

# Kurulum surecinin hala calistigi varsayilan sure: durum dosyasi "kuruluyor" ve 90 dakikadan yeni
function Test-ClamInstalling {
    if (-not (Test-Path $ClamStatusPath)) { return $false }
    $item = Get-Item $ClamStatusPath
    return ((Get-Content $ClamStatusPath -Raw).Trim() -eq 'kuruluyor') -and ((Get-Date) - $item.LastWriteTime).TotalMinutes -lt 90
}

$script:VtCache = @{}
$script:VtCalls = 0

# VirusTotal sonucu: kac motor zararli dedi, toplam motor, onerilen isim. Anahtar yoksa / hatada $null.
function Get-VirusTotalInfo([string]$sha256) {
    if ($script:VtCache.ContainsKey($sha256)) { return $script:VtCache[$sha256] }
    $cfg = Get-Config
    if (-not $cfg.vtKey) { return $null }
    $info = $null
    try {
        $script:VtCalls++
        $r = Invoke-RestMethod -Uri "https://www.virustotal.com/api/v3/files/$sha256" `
            -Headers @{ 'x-apikey' = $cfg.vtKey } -TimeoutSec 20 -UseBasicParsing
        $a = $r.data.attributes
        $stats = $a.last_analysis_stats
        $info = [pscustomobject]@{
            found     = $true
            malicious = [int]$stats.malicious
            total     = [int]$stats.malicious + [int]$stats.undetected + [int]$stats.harmless + [int]$stats.suspicious
            label     = [string]$a.popular_threat_classification.suggested_threat_label
        }
    } catch {
        $code = $_.Exception.Response.StatusCode.value__
        if ($code -eq 404) { $info = [pscustomobject]@{ found = $false; malicious = 0; total = 0; label = '' } }
        else { Write-Log "VirusTotal hatasi: $code" }
    }
    $script:VtCache[$sha256] = $info
    return $info
}

function Get-ZoneInfo([string]$file) {
    $z = @{}
    try {
        foreach ($line in Get-Content -LiteralPath $file -Stream Zone.Identifier -ErrorAction Stop) {
            if ($line -match '^(\w+)=(.*)$') { $z[$Matches[1]] = $Matches[2] }
        }
    } catch { }
    return $z
}

function Test-FromInternet([string]$file) {
    return (Get-ZoneInfo $file)['ZoneId'] -in @('3', '4')
}

function Get-UrlHost([string]$url) {
    try { return ([uri]$url).Host } catch { return $url }
}

$FileKinds = @{
    '.exe' = 'Program'; '.scr' = 'Ekran koruyucu (program gibi çalışır)'; '.com' = 'Program'; '.pif' = 'Program'
    '.msi' = 'Kurulum paketi'; '.msix' = 'Uygulama paketi'; '.msixbundle' = 'Uygulama paketi'; '.appx' = 'Uygulama paketi'
    '.dll' = 'Program kütüphanesi'; '.cpl' = 'Denetim masası öğesi (program gibi çalışır)'
    '.bat' = 'Komut dosyası'; '.cmd' = 'Komut dosyası'; '.ps1' = 'PowerShell scripti'; '.vbs' = 'VBScript'
    '.vbe' = 'VBScript (şifreli)'; '.js' = 'JavaScript'; '.jse' = 'JavaScript (şifreli)'; '.wsf' = 'Windows scripti'
    '.hta' = 'HTML uygulaması'; '.jar' = 'Java programı'; '.lnk' = 'Kısayol'; '.url' = 'İnternet kısayolu'
    '.zip' = 'Arşiv'; '.rar' = 'Arşiv'; '.7z' = 'Arşiv'; '.iso' = 'Disk görüntüsü'; '.img' = 'Disk görüntüsü'
    '.reg' = 'Kayıt defteri dosyası'
}

function Format-Size([long]$bytes) {
    if ($bytes -ge 1MB) { return '{0:N1} MB' -f ($bytes / 1MB) }
    return '{0:N0} KB' -f [math]::Max(1, $bytes / 1KB)
}

<#
  Sade dosya raporu: ne oldugu, ureticisi, imzasi, nereden geldigi ve tum motorlarin sonucu.
  $family: Cortmed veritabani sonucu ($null = kayitli degil). $vt: Get-VirusTotalInfo. $eng: Get-ContentScan.
#>
function Get-FileReport([string]$file, $family, $vt, $sig, $eng, [string]$verdict) {
    $item = Get-Item -LiteralPath $file -ErrorAction SilentlyContinue
    $ext = [IO.Path]::GetExtension($file).ToLowerInvariant()
    $kind = if ($FileKinds.ContainsKey($ext)) { $FileKinds[$ext] } else { "$ext dosyası" }
    $lines = @()
    $lines += "Dosya:  $([IO.Path]::GetFileName($file))"
    $lines += "Konum:  $file"
    $lines += "Tür:  $kind"
    if ($item) {
        $lines += "Boyut:  $(Format-Size $item.Length)"
        $lines += "Bilgisayara geliş:  {0:dd.MM.yyyy HH:mm}" -f $item.CreationTime
    }

    # Dosyanin kendi uzerinde yazan bilgiler; sahte olabilir, imza ile birlikte okunmali
    $vi = $null
    if ($ext -in $ProgramExtensions) { try { $vi = [Diagnostics.FileVersionInfo]::GetVersionInfo($file) } catch { } }
    if ($vi -and ($vi.ProductName -or $vi.FileDescription -or $vi.CompanyName)) {
        $what = @($vi.ProductName, $vi.FileDescription) | Where-Object { $_ } | Select-Object -Unique
        $ver = if ($vi.FileVersion) { " (sürüm $($vi.FileVersion.Trim()))" } else { '' }
        $lines += "Ne olduğu:  $($what -join ' – ')$ver"
        $lines += "Üretici (dosyada yazan):  $(if ($vi.CompanyName) { $vi.CompanyName } else { 'belirtilmemiş' })"
    } elseif ($ext -in $ProgramExtensions) {
        $lines += 'Ne olduğu:  Dosyada ürün veya üretici bilgisi yok'
    }
    if ($ext -eq '.lnk') {
        try {
            $l = (New-Object -ComObject WScript.Shell).CreateShortcut($file)
            $lines += "Kısayol hedefi:  $($l.TargetPath) $($l.Arguments)".TrimEnd()
        } catch { }
    }

    if ($sig) {
        $signer = if ($sig.SignerCertificate -and $sig.SignerCertificate.Subject -match 'CN="?([^",]+)') { $Matches[1] } else { '' }
        $sigText = switch ([string]$sig.Status) {
            'Valid' { "Geçerli – $signer (üretici doğrulanmış)" }
            'NotSigned' { 'İmzasız (üreticisi doğrulanamıyor)' }
            { $_ -in 'UnknownError', 'NotSupportedFileFormat', 'Incompatible' } { 'Okunamadı (gerçek bir program dosyası gibi görünmüyor; uzantısı yanıltıcı olabilir)' }
            'HashMismatch' { "Bozuk imza – dosya imzalandıktan sonra değiştirilmiş ($signer)" }
            default { "Geçersiz imza ($($sig.Status)) $signer".TrimEnd() }
        }
        $lines += "İmza:  $sigText"
    }

    $zone = if ($item) { Get-ZoneInfo $file } else { @{} }
    if ($zone['HostUrl']) {
        $lines += "Nereden indi:  $(Get-UrlHost $zone['HostUrl'])"
        if ($zone['ReferrerUrl']) { $lines += "İndirildiği sayfa:  $(Get-UrlHost $zone['ReferrerUrl'])" }
    } elseif ($zone['ZoneId'] -in @('3', '4')) {
        $lines += 'Nereden indi:  İnternetten (adres kaydedilmemiş)'
    } else {
        $lines += 'Nereden indi:  Bilinmiyor (bu bilgisayarda oluşmuş ya da kaynak bilgisi yok)'
    }

    $lines += ''
    $lines += '— Tarama motorları —'
    $dbText = if ($null -eq $family) { 'Kayıtlı değil' } elseif ($family) { "KAYITLI ZARARLI ($family)" } else { 'KAYITLI ZARARLI' }
    $lines += "Cortmed veritabanı:  $dbText"
    if ($eng) {
        $defText = switch ($eng.defender.status) {
            'found' { "ZARARLI BULDU: $($eng.defender.name)" }
            'clean' { 'Temiz' }
            default { 'Kullanılamadı (Defender kapalı ya da başka antivirüs var)' }
        }
        $lines += "Microsoft Defender:  $defText"
        $yaraText = if (-not $eng.yaraReady) { 'Kurulu değil' }
            elseif (-not $eng.yara) { 'Eşleşme yok' }
            else { "$(@($eng.yara).Count) kural eşleşti: " + ((@($eng.yara) | ForEach-Object { "$($_.rule) (puan $($_.score))" }) -join ', ') }
        $lines += "YARA kuralları:  $yaraText"
        $clamText = Get-ClamStatusText
        if (-not $clamText) {
            $clamText = if ($eng.clam) { "ZARARLI BULDU: $($eng.clam)" } elseif ($eng.clamRan) { 'Temiz' } else { 'Bu taramada çalıştırılmadı' }
        }
        $lines += "ClamAV:  $clamText"
    }
    $vtText = if (-not (Get-Config).vtKey) { 'Sorgulanmadı (Ayarlar''da API anahtarı yok)' }
        elseif ($null -eq $vt) { 'Sorgulanmadı ya da şu an ulaşılamadı' }
        elseif (-not $vt.found) { 'Bu dosya VirusTotal''da hiç görülmemiş' }
        else { "$($vt.malicious) / $($vt.total) antivirüs motoru zararlı dedi" + $(if ($vt.label) { " (isim: $($vt.label))" } else { '' }) }
    $lines += "VirusTotal:  $vtText"
    $lines += ''
    $lines += "Sonuç:  $verdict"
    return ($lines -join "`r`n")
}

# Bulguya kisa ozet ekler (bildirim icin) ve tam raporu baglar
function Add-Report($finding, [string]$file, $family, $vt, $sig, $eng, $risk) {
    $report = Get-FileReport $file $family $vt $sig $eng $finding.detail
    if ($risk) {
        # Cortmed'in kendi karari en ustte: puan ve nedenleri; motor ayrintilari altta
        $why = @("— Cortmed risk puanı: $($risk.score) / 100 —")
        if ($risk.reasons) { $why += @($risk.reasons | ForEach-Object { "•  $_" }) } else { $why += '•  Riskli bir özellik bulunmadı.' }
        $report = $report.Replace('— Tarama motorları —', (($why -join "`r`n") + "`r`n`r`n— Tarama motorları —"))
    }
    $finding | Add-Member -Force report $report
    if ($risk) { $finding | Add-Member -Force score $risk.score }
    $zone = Get-ZoneInfo $file
    if ($zone['HostUrl']) { $finding.detail += " (İndirildiği yer: $(Get-UrlHost $zone['HostUrl']))" }
    return $finding
}

# Taninmis markalar: imzasiz bir dosya kendini bunlardan biri gibi tanitiyorsa taklittir
$KnownBrands = @('Microsoft', 'Windows', 'Google', 'Chrome', 'Discord', 'Steam', 'Valve', 'Epic Games', 'Riot',
    'Adobe', 'NVIDIA', 'AMD', 'Intel', 'Mozilla', 'Firefox', 'Apple', 'Spotify', 'WhatsApp', 'Telegram', 'Opera', 'Zoom')
# Sohbet ve dosya paylasim siteleri: oyun/hile/"dene bunu" dosyalari genelde buralardan gelir
$ChatHosts = @('cdn.discordapp.com', 'media.discordapp.net', 'discord.com', 'discordapp.com', 't.me', 'telegram.org',
    'mega.nz', 'mediafire.com', 'gofile.io', 'anonfiles.com', 'pixeldrain.com', 'sendspace.com', 'catbox.moe')
$DocLikeExtensions = @('.pdf', '.doc', '.docx', '.xls', '.xlsx', '.ppt', '.txt', '.jpg', '.jpeg', '.png', '.gif', '.mp3', '.mp4', '.zip', '.rar')
$ScriptExtensions = @('.bat', '.cmd', '.ps1', '.vbs', '.vbe', '.js', '.jse', '.wsf', '.hta')

<#
  Cortmed'in kendi karar motoru: butun ipuclarini tek bir 0-100 risk puanina cevirir ve
  her puan icin kullanicinin anlayacagi bir neden yazar. Dis motorlar (Defender, ClamAV, VirusTotal)
  sadece ipuclarindan biridir; karari puan verir.
    70+   : Tehlikeli (kirmizi)
    40-69 : Supheli (Tehditler sekmesi, sari)
    15-39 : Taninmayan program (Onerilerimiz)
#>
function Get-RiskAssessment([string]$file, $family, $vt, $sig, $eng, [bool]$fromNet) {
    $ext = [IO.Path]::GetExtension($file).ToLowerInvariant()
    $name = [IO.Path]::GetFileName($file)
    $isProgram = $ext -in $ProgramExtensions
    $isScript = $ext -in $ScriptExtensions
    $reasons = New-Object Collections.Generic.List[string]
    $add = { param([int]$pts, [string]$why) $script:riskScore += $pts; $reasons.Add($why) }
    $script:riskScore = 0

    # Kesin bilgiler
    if ($null -ne $family) { & $add 100 'Bilinen bir virüsün birebir kopyası (Cortmed veritabanı).' }
    if ($eng.defender.status -eq 'found') { & $add 100 "Microsoft Defender da zararlı buldu ($($eng.defender.name))." }
    if ($vt -and $vt.malicious -ge 3) { & $add 90 "$($vt.malicious) farklı antivirüs programı bu dosyaya zararlı diyor." }
    elseif ($vt -and $vt.malicious -ge 1) { & $add 20 "$($vt.malicious) antivirüs programı bu dosyadan şüpheleniyor." }
    if ($eng.clam) {
        if ($eng.clam -match '^(PUA|Heuristics)\.') { & $add 30 'Ek tarama motoru istenmeyen program olabileceğini söylüyor.' }
        else { & $add 80 'Ek tarama motoru (ClamAV) zararlı buldu.' }
    }

    # Icerik kaliplari (YARA)
    $strong = @($eng.yara | Where-Object { $_.score -ge 75 -and $_.rule -notmatch 'SUSP|HKTL|PUA|HUNT' })
    $weak = @($eng.yara | Where-Object { $_.score -ge 50 -and $_ -notin $strong })
    if ($strong) { & $add 70 'İçinde bilinen bir zararlı yazılım ailesinin izleri var.' }
    elseif ($weak) { & $add 35 'İçinde zararlı programlarda sık görülen kod kalıpları var.' }

    # Imza ve kimlik
    $valid = $sig -and $sig.Status -eq 'Valid'
    if ($sig -and $sig.Status -eq 'HashMismatch') { & $add 60 'Dosya, üreticisi imzaladıktan sonra değiştirilmiş.' }
    elseif (($isProgram -or $isScript) -and -not $valid) { & $add 15 'Üreticisi doğrulanamıyor (imzasız).' }
    if ($isProgram -and -not $valid) {
        $vi = $null
        try { $vi = [Diagnostics.FileVersionInfo]::GetVersionInfo($file) } catch { }
        if ($vi) {
            $claims = "$($vi.CompanyName) $($vi.ProductName) $($vi.FileDescription)"
            $brand = $KnownBrands | Where-Object { $claims -match "(?i)\b$([regex]::Escape($_))\b" } | Select-Object -First 1
            if ($brand) { & $add 45 "Kendini $brand ürünü gibi gösteriyor ama $brand tarafından imzalanmamış." }
        }
    }

    # Ad hileleri
    if ($name -match [char]0x202E) { & $add 60 'Dosya adı, uzantıyı gizleyen ters çevrilmiş bir karakter içeriyor.' }
    $inner = [IO.Path]::GetExtension([IO.Path]::GetFileNameWithoutExtension($name)).ToLowerInvariant()
    if (($isProgram -or $isScript) -and $inner -in $DocLikeExtensions) {
        & $add 50 "Belge ya da resim gibi görünüyor ($inner) ama aslında çalıştırılabilir bir dosya."
    }

    # Nereden geldi
    if ($fromNet) {
        $host_ = Get-UrlHost ((Get-ZoneInfo $file)['HostUrl'])
        if (($isProgram -or $isScript) -and -not $valid -and $host_ -and ($ChatHosts | Where-Object { $host_ -eq $_ -or $host_.EndsWith(".$_") })) {
            & $add 25 "Bir sohbet ya da dosya paylaşım sitesinden ($host_) indirilmiş; oyun ve hile dosyası diye gönderilen virüsler genelde buradan gelir."
        } elseif ($isProgram -or $isScript) {
            & $add 10 'İnternetten indirilmiş.'
        }
        if ($isScript) { & $add 30 'İnternetten inen komut dosyaları ev kullanıcıları için nadiren gereklidir.' }
    }

    # Gizlenmis icerik
    if ($isProgram -and -not $valid) {
        try {
            $entropy = [Cortmed.CortmedDb]::Entropy($file, 8MB)
            if ($entropy -ge 7.4) { & $add 15 'İçeriği sıkıştırılmış ya da gizlenmiş; ne yaptığı dışarıdan görünmüyor.' }
        } catch { }
    }

    # Gecerli bir imza guveni artirir (ama kesin bulgulari sifirlamaz)
    if ($valid -and $script:riskScore -lt 100) {
        $signer = if ($sig.SignerCertificate.Subject -match 'CN="?([^",]+)') { $Matches[1] } else { 'üreticisi' }
        $script:riskScore -= 30
        $reasons.Add("Geçerli bir imzası var ($signer); bu güveni artırır.")
    }
    $score = [math]::Max(0, [math]::Min(100, $script:riskScore))
    return [pscustomobject]@{ score = $score; reasons = @($reasons) }
}

<#
  Bir dosyayi kontrol eder: once ipuclarini toplar (Cortmed veritabani, YARA, Defender, istege bagli ClamAV
  ve VirusTotal, imza, kaynak, ad hileleri), sonra Cortmed risk puanina gore karar verir.
  Temizse $null (ya da -AlwaysReport ile "OK" raporu) dondurur.
#>
function Test-FileThreat([string]$file, [switch]$UseVirusTotal, [switch]$SkipClam, [switch]$AlwaysReport) {
    $ext = [IO.Path]::GetExtension($file).ToLowerInvariant()
    $name = [IO.Path]::GetFileName($file)
    try { $h = [Cortmed.CortmedDb]::HashFile($file) } catch { return $null }
    $trusted = $h[0] -in @((Get-Config).trustedHashes)
    if ($trusted -and -not $AlwaysReport) { return $null }
    $family = $script:Db.LookupHex($h[0], $h[1])
    $isProgram = $ext -in $ProgramExtensions
    $fromNet = Test-FromInternet $file
    $eng = Get-ContentScan $file -SkipClam:$SkipClam
    $vt = if ($UseVirusTotal -and ($isProgram -or $fromNet -or $null -ne $family -or $AlwaysReport)) { Get-VirusTotalInfo $h[0] } else { $null }
    $sig = if ($isProgram -or $ext -in $ScriptExtensions) { Get-AuthenticodeSignature -FilePath $file -ErrorAction SilentlyContinue } else { $null }
    $risk = Get-RiskAssessment $file $family $vt $sig $eng $fromNet
    $top = if ($risk.reasons) { ' ' + $risk.reasons[0] } else { '' }

    $key = "file:$($h[0])"
    if ($trusted) {
        $f = New-Finding $key 'OK' "Güvendiğiniz dosya: $name" 'Bu dosyayı güvenilir olarak işaretlediniz; Cortmed onun için uyarı vermez.' $file
    } elseif ($risk.score -ge 70) {
        # Bilinen bir virus mu, yoksa Cortmed'in kendi ipuclariyla mi yakalandi?
        $known = ($null -ne $family) -or $eng.defender.status -eq 'found' -or ($vt -and $vt.malicious -ge 3) -or
            ($eng.clam -and $eng.clam -notmatch '^(PUA|Heuristics)\.')
        $title = if ($known) { "Virüs bulundu: $name" } else { "Tehlikeli dosya: $name" }
        $f = New-Finding $key 'RED' $title ("Bu dosya tehlikeli. Açmayın ve silin.$top") $file
    } elseif ($risk.score -ge 40) {
        $f = New-Finding $key 'YELLOW' "Şüpheli dosya: $name" ("Bu dosya şüpheli ama kesin virüs değil. Nereden geldiğini bilmiyorsanız açmayın.$top") $file
        $f | Add-Member -Force tab 'threat'
    } elseif ($risk.score -ge 15) {
        $f = New-Finding $key 'YELLOW' "Tanınmayan program: $name" `
            'Bu programın üreticisi doğrulanamıyor. Güvendiğiniz bir yerden indirdiyseniz sorun yok; emin değilseniz açmayın.' $file
    } elseif ($AlwaysReport) {
        $f = New-Finding $key 'OK' "Bilinen bir tehdit yok: $name" `
            'Bu dosyada riskli bir özellik bulunmadı. Yine de tanımadığınız birinden geldiyse açmayın.' $file
    } else {
        return $null
    }
    return Add-Report $f $file $family $vt $sig $eng $risk
}

# "Dosya Tara" icin: temiz olsa bile raporu dondurur
function Get-FileAnalysis([string]$file) {
    return Test-FileThreat $file -UseVirusTotal -AlwaysReport
}

function Invoke-Quarantine([string]$file) {
    try {
        $target = Join-Path $QuarantineDir ('{0:yyyyMMdd-HHmmss}_{1}.karantina' -f (Get-Date), [IO.Path]::GetFileName($file))
        Move-Item -LiteralPath $file -Destination $target -Force
        Write-Log "Karantina: $file -> $target"
        return $true
    } catch {
        Write-Log "Karantinaya alinamadi: $file ($_)"
        return $false
    }
}

# Kirmizi dosya bulgusu: ayara gore karantinaya al ya da hic dokunmadan sadece bildir
function Resolve-RedFile($threat) {
    if ((Get-Config).autoQuarantine -eq $true -and (Invoke-Quarantine $threat.path)) {
        $threat.detail += ' Karantinaya alındı.'
    } else {
        $threat.detail += ' Cortmed dosyayı silmedi; silmek size kalmış.'
    }
    return $threat
}

# ------------------------------------------------------------------ uyarilar

# -Sticky: kapatilana kadar ekranda kalir (sadece tehlikeli bulgular icin); digerleri kendiliginden kaybolur
# Bildirim gosterilsin mi? Kirmizi (Sticky) her zaman; digerleri Sessiz mod aciksa gosterilmez.
function Test-ToastAllowed([bool]$Sticky, $Config = $null) {
    if ($Sticky) { return $true }
    try { if ($null -eq $Config) { $Config = Get-Config } } catch { return $true }
    return -not ($Config.quietMode -eq $true)
}

function Show-Toast([string]$title, [string]$text, [switch]$Sticky) {
    if (-not (Test-ToastAllowed ([bool]$Sticky))) { return }
    try {
        [void][Windows.UI.Notifications.ToastNotificationManager, Windows.UI.Notifications, ContentType = WindowsRuntime]
        [void][Windows.Data.Xml.Dom.XmlDocument, Windows.Data.Xml.Dom.XmlDocument, ContentType = WindowsRuntime]
        $esc = { param($s) [Security.SecurityElement]::Escape($s) }
        $xml = New-Object Windows.Data.Xml.Dom.XmlDocument
        $scenario = if ($Sticky) { " scenario='reminder'" } else { '' }
        $actions = if ($Sticky) { "<actions><action content='Tamam' arguments='ok' activationType='system'/></actions>" } else { '' }
        $xml.LoadXml("<toast$scenario><visual><binding template='ToastGeneric'><text>$(& $esc $title)</text><text>$(& $esc $text)</text></binding></visual>$actions</toast>")
        # Baslat menusunde Cortmed kisayolu varsa bildirim Cortmed adi ve logosuyla gelir
        $appId = if (Test-Path (Join-Path ([Environment]::GetFolderPath('Programs')) 'Cortmed Security.lnk')) { 'Cortmed.Security' }
            else { '{1AC14E77-02E7-4E5D-B744-2EB1AE5198B7}\WindowsPowerShell\v1.0\powershell.exe' }
        [Windows.UI.Notifications.ToastNotificationManager]::CreateToastNotifier($appId).Show(
            [Windows.UI.Notifications.ToastNotification]::new($xml))
    } catch {
        Write-Log "Bildirim gosterilemedi: $_"
    }
}

# Kirmizi bulgu: bilgisayarda genel bir uyari bildirimi
function Raise-Red($findings) {
    if (-not $findings) { return }
    Show-Toast '⚠️ Cortmed Security - Güvenlik Uyarısı' (
        'Bilgisayarınızda tehlikeli bir dosya ya da ayar bulundu. Ayrıntılar için Cortmed Security''yi açın.') -Sticky
}

# ------------------------------------------------------------------ kontroller

function Get-PostureFindings {
    $out = @()
    try {
        $mp = Get-MpComputerStatus
        $otherAv = @(Get-CimInstance -Namespace root/SecurityCenter2 -ClassName AntiVirusProduct -ErrorAction SilentlyContinue |
            Where-Object { $_.displayName -notmatch 'Defender' })
        if ((-not $mp.AntivirusEnabled -or -not $mp.RealTimeProtectionEnabled) -and $otherAv.Count -eq 0) {
            $out += New-Finding 'defender-off' 'RED' 'Virüs koruması kapalı' `
                'Windows''un virüs koruması (Defender) kapalı. Başlat menüsünden "Windows Güvenliği"ni açıp Virüs ve tehdit koruması bölümünden açın. Siz kapatmadıysanız bunu bir virüs yapmış olabilir.'
        } elseif ($mp.AntivirusSignatureAge -gt 3) {
            $out += New-Finding 'defender-old' 'YELLOW' 'Virüs koruması güncel değil' `
                "Windows'un virüs listesi $($mp.AntivirusSignatureAge) gündür güncellenmedi. Ayarlar > Windows Update'ten güncellemeleri yükleyin."
        }
    } catch { }

    try {
        $pref = Get-MpPreference
        $weak = @()
        if ($pref.PUAProtection -ne 1) { $weak += 'istenmeyen uygulama engelleme' }
        if ($pref.EnableNetworkProtection -ne 1) { $weak += 'ağ koruması' }
        if ($weak) {
            $out += New-Finding 'defender-extra' 'YELLOW' 'Ek korumalar kapalı' `
                ("Windows'un ücretsiz ek korumaları kapalı (" + ($weak -join ', ') + "). Aşağıdaki 'Güvenliği Güçlendir' düğmesiyle tek seferde açabilirsiniz.")
        }
    } catch { }

    try {
        $off = @(Get-NetFirewallProfile | Where-Object { -not $_.Enabled } | ForEach-Object Name)
        if ($off) {
            $out += New-Finding 'firewall' 'YELLOW' 'Güvenlik duvarı kapalı' `
                'Güvenlik duvarı, internetten gelen izinsiz bağlantıları engeller. Aşağıdaki ''Güvenliği Güçlendir'' düğmesiyle açabilirsiniz.'
        }
    } catch { }

    try {
        $lua = (Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' -ErrorAction Stop).EnableLUA
        if ($lua -eq 0) {
            $out += New-Finding 'uac' 'YELLOW' 'İzin soran pencere kapalı' `
                'Normalde bir program bilgisayarda değişiklik yapmak istediğinde Windows size sorar. Bu özellik kapalı. Denetim Masası > Kullanıcı Hesapları > Kullanıcı Hesabı Denetimi ayarlarından açın.'
        }
    } catch { }

    try {
        $ss = Get-ItemProperty 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\System' -ErrorAction SilentlyContinue
        $ss2 = Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer' -ErrorAction SilentlyContinue
        if (($ss -and $ss.EnableSmartScreen -eq 0) -or ($ss2 -and $ss2.SmartScreenEnabled -eq 'Off')) {
            $out += New-Finding 'smartscreen' 'YELLOW' 'İndirme uyarıları kapalı' `
                'İnternetten indirilen tanınmayan programlar uyarı vermeden açılıyor. Windows Güvenliği > Uygulama ve tarayıcı denetimi bölümünden açın.'
        }
    } catch { }

    try {
        $groups = whoami /groups /fo csv | ConvertFrom-Csv
        if ($groups | Where-Object { $_.SID -eq 'S-1-5-32-544' }) {
            $out += New-Finding 'admin' 'YELLOW' 'Yönetici hesabı kullanılıyor' `
                'Günlük işler için yönetici olmayan ayrı bir hesap kullanmak, virüslerin bilgisayara yerleşmesini çok zorlaştırır. Ayarlar > Hesaplar > Diğer kullanıcılar.'
        }
    } catch { }

    try {
        $servers = @(Get-DnsClientServerAddress -AddressFamily IPv4 |
            Where-Object { $_.ServerAddresses } |
            Where-Object { (Get-NetAdapter -InterfaceIndex $_.InterfaceIndex -ErrorAction SilentlyContinue).Status -eq 'Up' } |
            ForEach-Object { $_.ServerAddresses })
        if ($servers -and -not ($servers | Where-Object { $_ -in $SafeDns })) {
            $out += New-Finding 'dns' 'YELLOW' 'Zararlı site engelleme kapalı' `
                "Dolandırıcı ve virüslü siteler açılmadan engellenmiyor. Aşağıdaki 'Güvenliği Güçlendir' düğmesiyle açabilirsiniz."
        }
    } catch { }

    try {
        $last = Get-HotFix | Where-Object InstalledOn | Sort-Object InstalledOn -Descending | Select-Object -First 1
        if ($last -and ((Get-Date) - $last.InstalledOn).TotalDays -gt 45) {
            $out += New-Finding 'updates' 'YELLOW' 'Windows güncellemeleri gecikmiş' `
                ("Son güncelleme {0:dd.MM.yyyy} tarihinde yüklenmiş. Güvenlik açıklarının kapanması için Ayarlar > Windows Update'ten güncelleyin." -f $last.InstalledOn)
        }
    } catch { }
    return $out
}

function Resolve-CommandPath([string]$cmd) {
    if (-not $cmd) { return $null }
    $cmd = [Environment]::ExpandEnvironmentVariables($cmd.Trim())
    if ($cmd.StartsWith('"')) { return $cmd.Substring(1, $cmd.IndexOf('"', 1) - 1) }
    $m = [regex]::Match($cmd, '^(.+?\.(exe|com|bat|cmd|vbs|js|ps1|scr))(\s|$)', 'IgnoreCase')
    if ($m.Success) { return $m.Groups[1].Value }
    return $cmd.Split(' ')[0]
}

function Test-UserWritable([string]$p) {
    $p = $p.ToLowerInvariant()
    foreach ($d in @($env:APPDATA, $env:LOCALAPPDATA, $env:TEMP, "$env:USERPROFILE\Downloads", $env:PUBLIC, $env:ProgramData)) {
        if ($d -and $p.StartsWith($d.ToLowerInvariant())) { return $true }
    }
    return $false
}

function Test-StartupEntry([string]$source, [string]$name, [string]$cmd) {
    $out = @()
    if ($cmd -match 'Cortmed') { return $out }
    $exe = Resolve-CommandPath $cmd
    $label = "$name ($source)"
    if ($cmd -match '(?i)(powershell|pwsh).*(-e(nc|ncodedcommand)?\s+[A-Za-z0-9+/=]{20,}|frombase64string)') {
        $out += New-Finding "persist-enc:$name" 'RED' "Gizli başlangıç komutu: $name" `
            'Bilgisayar her açıldığında gizlenmiş bir komut çalışıyor. Virüsler bu yöntemi sık kullanır. Bilgisayardan anlayan birine baktırın.' $exe
    } elseif ($cmd -match '(?i)\b(wscript|cscript|mshta|rundll32|regsvr32|powershell)\b' -and (Test-UserWritable $cmd)) {
        $out += New-Finding "persist-script:$name" 'YELLOW' "Açılışta çalışan komut: $name" `
            'Bilgisayar her açıldığında bir komut dosyası çalışıyor. Bunu siz kurmadıysanız Görev Yöneticisi > Başlangıç sekmesinden kapatın.' $exe
    }
    if ($exe -and (Test-Path -LiteralPath $exe -PathType Leaf)) {
        $threat = Test-FileThreat $exe -SkipClam
        if ($threat -and $threat.level -eq 'RED') {
            $threat.title = "Başlangıçta virüs çalışıyor: $label"
            $threat.detail = 'Bu zararlı program bilgisayar her açıldığında çalışıyor. Bilgisayardan anlayan birine baktırın.'
            $out += $threat
        } elseif ((Test-UserWritable $exe) -and [IO.Path]::GetExtension($exe) -in $ProgramExtensions) {
            $sig = Get-AuthenticodeSignature -FilePath $exe -ErrorAction SilentlyContinue
            if (-not $sig -or $sig.Status -ne 'Valid') {
                $out += New-Finding "persist-unsigned:$exe" 'YELLOW' "Açılışta çalışan tanınmayan program: $name" `
                    "Bu program bilgisayar her açıldığında çalışıyor ve üreticisi doğrulanamıyor. Tanımıyorsanız Görev Yöneticisi > Başlangıç sekmesinden kapatın." $exe
            }
        }
    }
    return $out
}

function Get-PersistenceFindings {
    $out = @()
    $runKeys = @('HKCU:\Software\Microsoft\Windows\CurrentVersion\Run', 'HKCU:\Software\Microsoft\Windows\CurrentVersion\RunOnce',
        'HKLM:\Software\Microsoft\Windows\CurrentVersion\Run', 'HKLM:\Software\Microsoft\Windows\CurrentVersion\RunOnce',
        'HKLM:\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Run')
    foreach ($k in $runKeys) {
        $item = Get-ItemProperty $k -ErrorAction SilentlyContinue
        if (-not $item) { continue }
        foreach ($p in $item.PSObject.Properties | Where-Object { $_.Name -notlike 'PS*' }) {
            $out += Test-StartupEntry $k.Split('\')[-1] $p.Name ([string]$p.Value)
        }
    }

    $shell = New-Object -ComObject WScript.Shell
    foreach ($dir in @([Environment]::GetFolderPath('Startup'), [Environment]::GetFolderPath('CommonStartup'))) {
        foreach ($f in Get-ChildItem $dir -File -ErrorAction SilentlyContinue | Where-Object Name -ne 'desktop.ini') {
            $cmd = if ($f.Extension -eq '.lnk') {
                $l = $shell.CreateShortcut($f.FullName); ('"{0}" {1}' -f $l.TargetPath, $l.Arguments)
            } else { '"{0}"' -f $f.FullName }
            if ($f.Extension -in @('.vbs', '.js', '.bat', '.cmd', '.ps1', '.hta') -and $f.Name -notmatch 'Cortmed') {
                $out += New-Finding "startup-script:$($f.Name)" 'YELLOW' "Açılışta çalışan komut dosyası: $($f.Name)" `
                    'Bilgisayar her açıldığında bir komut dosyası çalışıyor. Bunu siz eklemediyseniz silin ya da bilgisayardan anlayan birine sorun.' $f.FullName
            }
            $out += Test-StartupEntry 'Başlangıç klasörü' $f.BaseName $cmd
        }
    }

    try {
        foreach ($t in Get-ScheduledTask -ErrorAction Stop | Where-Object { $_.TaskPath -notlike '\Microsoft\*' -and $_.State -ne 'Disabled' }) {
            foreach ($a in $t.Actions | Where-Object { $_.Execute }) {
                $out += Test-StartupEntry 'Zamanlanmış görev' $t.TaskName ('"{0}" {1}' -f $a.Execute, $a.Arguments)
            }
        }
    } catch { }
    return $out
}

# Discord token hirsizlari Discord'un cekirdek dosyasina kod enjekte eder
function Get-DiscordFindings {
    $out = @()
    foreach ($base in Get-ChildItem $env:LOCALAPPDATA -Directory -Filter 'Discord*' -ErrorAction SilentlyContinue) {
        $files = Get-ChildItem $base.FullName -Recurse -Filter 'index.js' -ErrorAction SilentlyContinue |
            Where-Object { $_.FullName -match '\\modules\\discord_desktop_core-[^\\]+\\discord_desktop_core\\index\.js$' }
        foreach ($f in $files) {
            $content = (Get-Content $f.FullName -Raw -ErrorAction SilentlyContinue)
            if ($null -eq $content) { continue }
            if ($content.Trim() -ne "module.exports = require('./core.asar');") {
                $out += New-Finding "discord:$($f.FullName)" 'RED' "Discord programı değiştirilmiş" `
                    ("Discord'un kendi dosyalarından biri değiştirilmiş. Bu, hesap çalan programların bıraktığı bir iz olabilir. " +
                    "Discord'u kaldırıp yeniden kurun, şifrenizi değiştirin ve iki adımlı doğrulamayı açın. (Discord eklentisi kullanıyorsanız bu uyarı ondan olabilir.)") $f.FullName
            }
        }
    }
    return $out
}

function Get-WatchDirs {
    $dirs = @("$env:USERPROFILE\Downloads", [Environment]::GetFolderPath('Desktop'))
    $cfg = Get-Config
    if ($cfg.watchDirs) { $dirs += @($cfg.watchDirs) }
    return $dirs | Where-Object { $_ -and (Test-Path $_) } | Select-Object -Unique
}

# Indirilenler/Masaustu'ndeki riskli dosyalar; degismeyen dosyalar onbellekten gelir
function Get-DownloadFindings {
    $out = @()
    $cache = @{}
    $old = Read-Json $CachePath $null
    if ($old) { foreach ($p in $old.PSObject.Properties) { $cache[$p.Name] = $p.Value } }
    $newCache = @{}
    $vtBudget = 4
    $vtStart = $script:VtCalls
    $todo = @()
    foreach ($dir in Get-WatchDirs) {
        $files = Get-ChildItem $dir -Recurse -File -ErrorAction SilentlyContinue |
            Where-Object { $_.Extension.ToLowerInvariant() -in $RiskyExtensions -and $_.Length -lt 300MB }
        foreach ($f in $files) {
            $sig = '{0}|{1}|{2}' -f $f.FullName, $f.Length, $f.LastWriteTimeUtc.Ticks
            if ($cache.ContainsKey($sig) -and $script:Db.BuildTime -le [long]$cache[$sig]) {
                $newCache[$sig] = $cache[$sig]; continue
            }
            $todo += [pscustomobject]@{ file = $f; sig = $sig }
        }
    }
    $script:ClamResults = if (Test-ClamReady) { Invoke-ClamScan @($todo | ForEach-Object { $_.file.FullName }) } else { $null }
    foreach ($t in $todo) {
        $f = $t.file; $sig = $t.sig
        # Ucretsiz VirusTotal dakikada 4 sorguya izin verir: gercekten yapilan sorgulari say
        $useVt = ($script:VtCalls - $vtStart) -lt $vtBudget
        $threat = Test-FileThreat $f.FullName -UseVirusTotal:$useVt
        if ($threat -and $threat.level -eq 'RED') { $threat = Resolve-RedFile $threat }
        if ($threat) { $out += $threat }
        else { $newCache[$sig] = $script:Db.BuildTime }
    }
    $script:ClamResults = $null
    Write-Json $CachePath ([pscustomobject]$newCache)
    return $out
}

# Gece isinin imza anahtarinin acik yarisi (engine/sign_db.py --generate ciktisi)
$DbPublicX = '26e0318081d8d3d4defd932169992251c7f4d08d46a95f395ccd22c1c48c72c5'
$DbPublicY = '13cd8f7df0bdca9f67cd720e1f42e4174033842a5601d9c98bf68e2ef2402f4f'

# Dosyayi indirir ve imzali listedeki parmak iziyle birebir ayni oldugunu dogrular
function Get-VerifiedFile([string]$url, [string]$target, $expected) {
    Invoke-WebRequest $url -OutFile $target -UseBasicParsing -TimeoutSec 600
    $sha = (Get-FileHash -Algorithm SHA256 -LiteralPath $target).Hash.ToLowerInvariant()
    if ($sha -ne $expected.sha256) {
        Remove-Item $target -Force -ErrorAction SilentlyContinue
        throw "parmak izi tutmuyor: $url"
    }
}

function Update-Database {
    $cfg = Get-Config
    $base = ([string]$cfg.updateUrl).Trim().TrimEnd('/')
    if (-not $base) { return 'Güncelleme adresi ayarlı değil' }
    try {
        [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
        Initialize-EngineType
        # Once imzali dosya listesi: imza Cortmed'in gizli anahtariyla atilmamissa hicbir sey indirilmez
        $manifestBytes = (Invoke-WebRequest "$base/manifest.json" -UseBasicParsing -TimeoutSec 30).Content
        if ($manifestBytes -is [string]) { $manifestBytes = [Text.Encoding]::UTF8.GetBytes($manifestBytes) }
        $sigFile = Join-Path $DataDir 'manifest.sig.tmp'
        Invoke-WebRequest "$base/manifest.sig" -OutFile $sigFile -UseBasicParsing -TimeoutSec 30
        $sig = [IO.File]::ReadAllBytes($sigFile); Remove-Item $sigFile -Force
        if (-not [Cortmed.Signing]::Verify($manifestBytes, $sig, $DbPublicX, $DbPublicY)) {
            throw 'imza dogrulanamadi; guncelleme reddedildi'
        }
        $manifest = [Text.Encoding]::UTF8.GetString($manifestBytes) | ConvertFrom-Json
        $remote = $manifest.version
        $verFile = Join-Path $DataDir 'db-version.txt'
        if ((Test-Path $verFile) -and (Get-Content $verFile -Raw).Trim() -eq $remote) {
            return "Veritabanı zaten güncel ($remote)"
        }
        $tmp = Join-Path $DataDir 'windows.cmdb.tmp'
        Get-VerifiedFile "$base/windows.cmdb" $tmp $manifest.files.'windows.cmdb'
        # Bozuk ya da yarim veritabanini asla kullanma
        $new = [Cortmed.CortmedDb]::Load($tmp)
        if ($script:Db -and -not (Test-DbAcceptable $new $script:Db)) {
            Remove-Item $tmp -Force
            throw "indirilen veritabani reddedildi ($($new.SignatureCount) imza)"
        }
        $ytmp = Join-Path $DataDir 'windows.yarc.tmp'
        Get-VerifiedFile "$base/windows.yarc" $ytmp $manifest.files.'windows.yarc'
        Move-Item $tmp (Join-Path $DataDir 'windows.cmdb') -Force
        Move-Item $ytmp (Join-Path $DataDir 'windows.yarc') -Force
        # Surum ancak her sey indikten sonra kaydedilir; yarida kalirsa bir sonraki denemede tekrar indirilir
        Set-Content $verFile $remote
        Initialize-Engine
        Write-Log "Veritabani guncellendi (imza dogrulandi): $remote"
        return "Veritabanı güncellendi ($remote)"
    } catch {
        Write-Log "Veritabani guncellenemedi: $_"
        return $null
    }
}

function Invoke-FullScan {
    Initialize-Engine
    $findings = @()
    $findings += Get-PostureFindings
    $findings += Get-DiscordFindings
    $findings += Get-PersistenceFindings
    $findings += Get-DownloadFindings
    $findings = @($findings | Where-Object { $_ } | Sort-Object { if ($_.level -eq 'RED') { 0 } else { 1 } })

    # Ayni sey icin iki kez uyari yok: daha once bildirilen kirmizilar hatirlanir
    $prev = Read-Json $StatusPath $null
    $alerted = @(if ($prev -and $prev.alerted) { $prev.alerted })
    $reds = @($findings | Where-Object level -eq 'RED')
    $fresh = @($reds | Where-Object { $_.key -notin $alerted })
    $status = [pscustomobject]@{
        time       = (Get-Date).ToString('o')
        dbTime     = $script:Db.BuildTime
        signatures = $script:Db.SignatureCount
        findings   = $findings
        alerted    = @($reds | ForEach-Object key)
    }
    Write-Json $StatusPath $status
    Write-Log ("Tam tarama: {0} kirmizi, {1} sari" -f $reds.Count, ($findings.Count - $reds.Count))
    if ($fresh) { Raise-Red $fresh }
    return $status
}

# Bekcinin buldugu dosya tehditlerini durum dosyasina ekler
# "Bu dosyaya guveniyorum": parmak izini guvenilir listesine ekler ve bulguyu kaldirir
function Set-FileTrusted($finding) {
    $sha = ($finding.key -split ':')[-1]
    $cfg = Get-Config
    $cfg.trustedHashes = @(@($cfg.trustedHashes) + $sha | Where-Object { $_ } | Select-Object -Unique)
    Save-Config $cfg
    $status = Read-Json $StatusPath $null
    if ($status) {
        $status.findings = @($status.findings | Where-Object { $_ -and $_.key -ne $finding.key })
        Write-Json $StatusPath $status
    }
    Write-Log "Guvenilir olarak isaretlendi: $($finding.path)"
}

function Add-StatusFinding($finding) {
    $status = Read-Json $StatusPath ([pscustomobject]@{ time = (Get-Date).ToString('o'); findings = @(); alerted = @() })
    $list = @($status.findings | Where-Object { $_ -and $_.key -ne $finding.key }) + $finding
    $status.findings = @($list | Sort-Object { if ($_.level -eq 'RED') { 0 } else { 1 } })
    if ($finding.level -eq 'RED') { $status.alerted = @($status.alerted) + $finding.key }
    if ($script:Db) {
        $status | Add-Member -Force signatures $script:Db.SignatureCount
        $status | Add-Member -Force dbTime $script:Db.BuildTime
    }
    Write-Json $StatusPath $status
}

# ------------------------------------------------------------------ bekci

# Beklemeden tek kontrol: 'ready' (taranabilir), 'gone' (silinmis) ya da 'busy' (hala yaziliyor; sonra tekrar dene).
# Bekci tepsi simgesiyle ayni is parcaciginda calistigi icin burada asla uyunmaz.
function Test-FileReady([string]$file) {
    if (-not [IO.File]::Exists($file)) { return 'gone' }
    try {
        $fs = [IO.File]::Open($file, 'Open', 'Read', 'ReadWrite')
        $fs.Close()
        return 'ready'
    } catch { return 'busy' }
}

function Test-WatcherRunning {
    $m = $null
    try { return [Threading.Mutex]::TryOpenExisting('Local\CortmedSecurityWatcher', [ref]$m) }
    catch { return $false }
    finally { if ($m) { $m.Dispose() } }
}

$LauncherExe = Join-Path $Root 'CortmedSecurity.exe'

function Start-Background([string]$mode) {
    if (Test-Path $LauncherExe) {
        if ($mode -eq 'Watch') { return Start-Process $LauncherExe -ArgumentList '--watch' -PassThru }
        return Start-Process $LauncherExe -PassThru
    }
    $vbs = Join-Path $Root "cortmed-$($mode.ToLower()).vbs"
    if (Test-Path $vbs) { Start-Process wscript.exe ('"{0}"' -f $vbs); return $null }
    return Start-Process powershell.exe -WindowStyle Hidden -PassThru -ArgumentList @('-NoProfile', '-ExecutionPolicy', 'Bypass',
        '-File', ('"{0}"' -f (Join-Path $Root 'CortmedSecurity.ps1')), '-Mode', $mode)
}

# Tam tarama ayri bir surecte calisir; boylece pencere ve tepsi simgesi donmaz
function Start-ScanProcess {
    if (Test-Path $LauncherExe) { return Start-Process $LauncherExe -ArgumentList '--scan' -PassThru }
    return Start-Process powershell.exe -WindowStyle Hidden -PassThru -ArgumentList @('-NoProfile', '-ExecutionPolicy', 'Bypass',
        '-File', ('"{0}"' -f (Join-Path $Root 'CortmedSecurity.ps1')), '-Mode', 'Daily')
}

# Davranis bekcisinin bulgulari (findings.json). Dosya yok ya da bozuksa bulgu yok, hata yok.
# Bunlar gecmis kayittir, etkin tehdit degil: kirmizi bulgu ancak kullanici "kapat" dedikten sonra yazilir.
# Bu yuzden Onerilerimiz'de "Durdurulan programlar" altinda, sari olarak gorunur (tepsi kirmiziya donmez);
# ozgun seviye guardLevel'da saklanir.
function Get-GuardFindings {
    try {
        $file = Join-Path $GuardDataDir 'findings.json'
        if (-not [IO.File]::Exists($file)) { return }
        $items = [IO.File]::ReadAllText($file, [Text.Encoding]::UTF8) | ConvertFrom-Json
        foreach ($i in @($items)) {
            if (-not $i -or -not $i.key -or [string]$i.level -notin 'RED', 'YELLOW') { continue }
            $detail = [string]$i.detail
            $when = $null
            if ($i.PSObject.Properties['time'] -and $i.time) {
                try { $when = [datetime]::Parse([string]$i.time, [Globalization.CultureInfo]::InvariantCulture, 'RoundtripKind').ToLocalTime() } catch { }
            }
            if ($when) { $detail = '{0:dd.MM.yyyy HH:mm} · {1}' -f $when, $detail }
            $f = New-Finding ([string]$i.key) 'YELLOW' ([string]$i.title) $detail ([string]$i.path)
            $f | Add-Member -NotePropertyName guardLevel -NotePropertyValue ([string]$i.level)
            $f | Add-Member -NotePropertyName tab -NotePropertyValue 'advice'
            $f | Add-Member -NotePropertyName report -NotePropertyValue ([string]$i.report)
            $f
        }
    } catch { }
}

# Yeni "supheli davranis" (Warn, ozgun seviye sari) bulgulari: anahtar basina bir kez kisa, kalici olmayan bildirim.
# Gosterilen anahtarlar tepsinin kendi veri klasorunde (data\guard-warn-shown.txt) tutulur; dosya yazilamazsa
# bu oturumda yine de bir kez gosterilir. $notify: { param($title, $text, $sticky) }. Donus: gosterilen sayisi.
$GuardWarnShownPath = Join-Path $DataDir 'guard-warn-shown.txt'
$script:GuardWarnShown = @{}
function Invoke-GuardWarnNotices([scriptblock]$notify) {
    try {
        if ([IO.File]::Exists($GuardWarnShownPath)) {
            foreach ($l in [IO.File]::ReadAllLines($GuardWarnShownPath, [Text.Encoding]::UTF8)) { if ($l) { $script:GuardWarnShown[$l] = $true } }
        }
    } catch { }
    $n = 0
    foreach ($f in @(Get-GuardFindings)) {
        $key = [string]$f.key
        if ($f.guardLevel -ne 'YELLOW' -or $script:GuardWarnShown.ContainsKey($key)) { continue }
        $script:GuardWarnShown[$key] = $true
        try { [IO.File]::AppendAllText($GuardWarnShownPath, "$key`r`n", (New-Object Text.UTF8Encoding($false))) } catch { }
        $name = if ($f.path) { Split-Path ([string]$f.path) -Leaf } else { [string]$f.title }
        if ($notify) {
            & $notify 'Cortmed Security' "Şüpheli davranış: $name. Program durdurulmadı; ayrıntılar Önerilerimiz > Şüpheli davranan programlar bölümünde." $false
        }
        $n++
    }
    return $n
}

# Davranis bekcisi durumu. Tepsideki baglanti varsa Sysmon bilgisi ondan, yoksa isaret dosyalari ve hizmetlerden.
# Panel ayri bir surectir ve boruya baglanmaz (tek istemcili boru tepsinindir); istemcisiz cagirir.
function Get-GuardStatus($client = $null) {
    $r = @{ installed = $false; running = $false; sysmonOk = $false; preexisting = $false }
    try {
        $svc = Get-Service CortmedGuard -ErrorAction SilentlyContinue
        $r.installed = [bool]$svc
        $r.running = [bool]($svc -and $svc.Status -eq 'Running')
        if ($client -and $client.Connected) {
            $r.sysmonOk = $client.SysmonOk; $r.preexisting = $client.SysmonPreexisting
        } else {
            $r.sysmonOk = [bool](Get-Service Sysmon64, Sysmon -ErrorAction SilentlyContinue | Where-Object { $_.Status -eq 'Running' })
            $r.preexisting = (Test-Path (Join-Path $GuardDataDir 'sysmon-preexisting')) -and
                -not (Test-Path (Join-Path $GuardDataDir 'sysmon-installed-by-cortmed'))
        }
    } catch { }
    return $r
}

# Panel durum kartindaki dorduncu kontrol. offer: "Davranis bekcisini acin" karti gosterilsin; hint: kartin metni.
function Get-GuardCheck($gs) {
    if (-not $gs.installed) { return @{ ok = $false; text = 'Davranış bekçisi kapalı'; offer = $true } }
    if (-not $gs.running) {
        return @{ ok = $false; text = 'Davranış bekçisi çalışmıyor'; offer = $true
            hint = 'Davranış bekçisi çalışmıyor. Bilgisayarı yeniden başlatın; düzelmezse ''Davranış bekçisini açın'' ile yeniden kurun.' }
    }
    if ($gs.preexisting) { return @{ ok = $false; text = 'Sysmon başka bir ayarla çalışıyor' } }
    if (-not $gs.sysmonOk) { return @{ ok = $false; text = 'Davranış bekçisi tam çalışmıyor' } }
    return @{ ok = $true; text = 'Davranış bekçisi açık' }
}

# 64 bit Program Files, ortam degiskeni olmadan (Uninstall.ps1 ile ayni yontem): 64 bit islemde [Environment],
# 32 bit islemde kayit defterindeki ProgramW6432Dir.
function Get-ProgramFilesDir {
    $pf = [Environment]::GetFolderPath('ProgramFiles')
    if (-not [Environment]::Is64BitProcess) {
        $w6432 = (Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion' -Name ProgramW6432Dir -ErrorAction SilentlyContinue).ProgramW6432Dir
        if ($w6432) { $pf = $w6432 }
    }
    return $pf
}

# Windows klasoru ya da Program Files altinda mi (karantina teklif edilmez, otomatik karantina atlanir)
function Test-GuardSystemPath([string]$path) {
    if (-not $path) { return $false }
    $roots = @([Environment]::GetFolderPath('Windows'), [Environment]::GetFolderPath('ProgramFiles'),
        [Environment]::GetFolderPath('ProgramFilesX86'), (Get-ProgramFilesDir)) | Where-Object { $_ }
    foreach ($r in $roots) {
        if ($path.StartsWith($r.TrimEnd('\') + '\', [StringComparison]::OrdinalIgnoreCase)) { return $true }
    }
    return $false
}

# "Bekciyi ac" dugmesinin yukseltecegi kurulum betigi.
#   Hizmet varsa (onarim): YALNIZCA Program Files\Cortmed'deki, kullanicinin yazamadigi kopya ve kaynaklari;
#   o kopya yoksa (eski kurulum) kullanici klasorundeki kopya yukseltilmez, missing = $true.
#   Hizmet yoksa (ilk kurulum, henuz yonetici kopyasi yok): paketten kurulan $Root kopyasi, paketi calistirmakla ayni.
function Get-GuardSetupCommand([bool]$serviceExists, [string]$programFiles = (Get-ProgramFilesDir)) {
    if ($serviceExists) {
        $app = Join-Path $programFiles 'Cortmed'
        $script = Join-Path $app 'Install-Guard.ps1'
        if (Test-Path -LiteralPath $script -PathType Leaf) { return @{ script = $script; source = $app; missing = $false } }
        return @{ script = $null; source = $null; missing = $true }
    }
    $script = Join-Path $Root 'Install-Guard.ps1'
    if (Test-Path -LiteralPath $script -PathType Leaf) { return @{ script = $script; source = $Root; missing = $false } }
    return @{ script = $null; source = $null; missing = $true }
}

# Install-Guard.ps1 cikis koduna gore kullaniciya not (0 ya da bilinmiyorsa not yok)
function Get-GuardSetupNote($code) {
    if ($null -eq $code -or $code -eq 0) { return $null }
    if ($code -eq 2) { return 'Davranış bekçisi kuruldu ama Sysmon kurulamadı; bazı davranışlar görülmeyebilir.' }
    return 'Davranış bekçisi kurulamadı. Bilgisayarı yeniden başlatıp tekrar deneyin.'
}

function Get-StatusSummary {
    $s = Read-Json $StatusPath $null
    $all = @(if ($s) { $s.findings | Where-Object { $_ -and $_.level -in 'RED', 'YELLOW' } })
    $keys = @{}
    foreach ($f in $all) { $keys[[string]$f.key] = $true }
    $all += @(Get-GuardFindings | Where-Object { -not $keys.ContainsKey([string]$_.key) })
    [pscustomobject]@{
        status  = $s
        reds    = @($all | Where-Object { $_.level -eq 'RED' })
        threats = @($all | Where-Object { (Get-FindingTab $_) -eq 'threat' })
        advice  = @($all | Where-Object { (Get-FindingTab $_) -eq 'advice' })
        time    = if ($s -and $s.time) { [datetime]$s.time } else { $null }
    }
}

# ------------------------------------------------------------------ bekci (sistem tepsisi)

function New-StatusIcon([Drawing.Color]$dot) {
    $bmp = New-Object Drawing.Bitmap 32, 32
    $g = [Drawing.Graphics]::FromImage($bmp)
    # Kucuk boyutta keskin gorunsun diye amblemin sade cizimi: mavi serit, koyu bantlar, beyaz koseli C
    $fill = { param($c, $x, $y, $w, $h) $g.FillRectangle((New-Object Drawing.SolidBrush $c), $x, $y, $w, $h) }
    & $fill ([Drawing.Color]::FromArgb(7, 20, 42)) 0 0 32 32
    & $fill $UiAccent 0 0 9 32
    & $fill ([Drawing.Color]::FromArgb(10, 10, 14)) 9 0 23 6
    & $fill ([Drawing.Color]::FromArgb(10, 10, 14)) 9 26 23 6
    & $fill ([Drawing.Color]::White) 14 10 16 4
    & $fill ([Drawing.Color]::White) 14 19 16 4
    & $fill ([Drawing.Color]::White) 26 10 4 13
    $g.SmoothingMode = 'AntiAlias'
    $g.FillEllipse((New-Object Drawing.SolidBrush ([Drawing.Color]::FromArgb(7, 16, 30))), 17, 17, 15, 15)
    $g.FillEllipse((New-Object Drawing.SolidBrush $dot), 19, 19, 11, 11)
    $g.Dispose()
    return [Drawing.Icon]::FromHandle($bmp.GetHicon())
}

function Start-Watcher {
    $mutex = New-Object Threading.Mutex($false, 'Local\CortmedSecurityWatcher')
    if (-not $mutex.WaitOne(0)) { Write-Log 'Bekci zaten calisiyor'; return }
    Initialize-Engine
    try { [Cortmed.AppIdentity]::ApplyToProcess() } catch { }
    Write-Log "Bekci basladi ($($script:Db.SignatureCount) imza)"

    # Dosya olaylari gizli bir pencere uzerinden ana is parcacigina gelir; tepsi simgesi ayni dongude calisir
    $hostForm = New-Object Windows.Forms.Form
    $null = $hostForm.Handle
    $pending = @{}
    $watchers = @()
    foreach ($dir in Get-WatchDirs) {
        $w = New-Object IO.FileSystemWatcher $dir
        $w.IncludeSubdirectories = $true
        $w.NotifyFilter = [IO.NotifyFilters]'FileName, LastWrite, Size'
        $w.SynchronizingObject = $hostForm
        $onFile = {
            param($sender, $e)
            if ([IO.Path]::GetExtension($e.FullPath).ToLowerInvariant() -in $RiskyExtensions) { $pending[$e.FullPath] = Get-Date }
        }
        $w.add_Created($onFile); $w.add_Changed($onFile); $w.add_Renamed($onFile)
        $w.EnableRaisingEvents = $true
        $watchers += $w
    }

    $iconOk = New-StatusIcon $UiLevel.OK
    $iconRed = New-StatusIcon $UiLevel.RED
    $tray = New-Object Windows.Forms.NotifyIcon
    $tray.Icon = $iconOk
    $tray.Text = 'Cortmed Security'
    $menu = New-Object Windows.Forms.ContextMenuStrip
    $menu.ShowImageMargin = $true
    $menu.Font = New-Object Drawing.Font('Segoe UI', 10)
    $miOpen = New-Object Windows.Forms.ToolStripMenuItem 'Cortmed Security''yi aç'
    $miOpen.Font = New-Object Drawing.Font('Segoe UI Semibold', 10)
    $miScan = New-Object Windows.Forms.ToolStripMenuItem 'Şimdi tara'
    $miStop = New-Object Windows.Forms.ToolStripMenuItem 'Korumayı durdur'
    [void]$menu.Items.AddRange(@($miOpen, $miScan, (New-Object Windows.Forms.ToolStripSeparator), $miStop))
    $miOpen.Image = New-MenuGlyph 'open'; $miScan.Image = New-MenuGlyph 'scan'; $miStop.Image = New-MenuGlyph 'stop'
    Set-DarkMenuStyle $menu
    $tray.ContextMenuStrip = $menu

    $state = @{ lastDaily = [datetime]::MinValue; busy = $false; ticks = 0 }
    $prev = Read-Json $StatusPath $null
    if ($prev -and $prev.time) { try { $state.lastDaily = [datetime]$prev.time } catch { } }
    $seen = @{}
    $tries = @{}

    # Davranis bekcisi hizmetine tek baglanti (kendi arka plan okuyucusu var); sorular zamanlayicida alinir
    $guard = @{ client = $null; state = (New-GuardState) }
    try { $guard.client = New-Object Cortmed.GuardClient 'CortmedGuard' } catch { Write-Log "Bekci baglantisi kurulamadi: $_" }
    # true: cevap hizmete yazildi; false: yazilamadi (pencere acik kalir, kullanici yeniden dener)
    $guardAnswer = {
        param($id, $decision)
        $c = $guard.client
        $ok = $false
        if ($c -and $c.Connected) { $ok = [bool]$c.Answer($id, $decision) }
        if (-not $ok) {
            Show-Toast 'Cortmed Security' 'Koruma hizmetine şu an ulaşılamadı. Birkaç saniye sonra yeniden deneyin.'
            return $false
        }
        Write-Log "Bekci sorusu cevaplandi: $id $decision"
        return $true
    }
    $guardNotify = { param($title, $text, $sticky) if ($sticky) { Show-Toast $title $text -Sticky } else { Show-Toast $title $text } }

    $updateTray = {
        $sum = Get-StatusSummary
        if ($sum.reds.Count) { $tray.Icon = $iconRed; $line = "Dikkat: $($sum.reds.Count) tehdit bulundu" }
        else { $tray.Icon = $iconOk; $line = 'Koruma aktif · Güvendesiniz' }
        $tip = "Cortmed Security`n$line"
        if ($sum.time) { $tip += "`nSon tarama: {0:dd.MM HH:mm}" -f $sum.time }
        if ($tip.Length -gt 63) { $tip = $tip.Substring(0, 63) }
        $tray.Text = $tip
    }

    $miOpen.add_Click({ [void](Start-Background 'Panel') })
    $tray.add_MouseClick({ param($s, $e) if ($e.Button -eq 'Left') { [void](Start-Background 'Panel') } })
    $miScan.add_Click({
        [void](Start-ScanProcess)
        $tray.ShowBalloonTip(3000, 'Cortmed Security', 'Tarama başladı. Sonuç birkaç dakika içinde hazır olur.', 'Info')
    })
    $miStop.add_Click({
        $a = [Windows.Forms.MessageBox]::Show('Gerçek zamanlı koruma durdurulsun mu? Bilgisayar yeniden açılınca kendiliğinden tekrar başlar.',
            'Cortmed Security', 'YesNo', 'Question')
        if ($a -eq 'Yes') { Write-Log 'Bekci kullanici tarafindan durduruldu'; $tray.Visible = $false; [Windows.Forms.Application]::Exit() }
    })

    $timer = New-Object Windows.Forms.Timer
    $timer.Interval = 1000
    $timer.Add_Tick({
        if ($state.busy) { return }
        $state.busy = $true
        try {
            if ($guard.client) {
                try { Invoke-GuardTick $guard.state $guard.client (Get-Date) $guardAnswer $guardNotify }
                catch { Write-Log "Bekci sorusu hatasi: $_" }
            }
            $ready = @($pending.Keys | Where-Object { ((Get-Date) - $pending[$_]).TotalSeconds -ge 1.5 })
            foreach ($file in $ready) {
                $pending.Remove($file)
                if ($file -match '\\Karantina\\') { continue }
                $fileState = Test-FileReady $file
                if ($fileState -eq 'busy') {
                    # Hala yaziliyor (buyuk indirme): 30 dakikaya kadar birkac saniyede bir tekrar bak
                    $tries[$file] = 1 + [int]$tries[$file]
                    if ($tries[$file] -lt 600) { $pending[$file] = Get-Date }
                    continue
                }
                $tries.Remove($file)
                if ($fileState -ne 'ready') { continue }
                try {
                    $info = Get-Item -LiteralPath $file
                    $sig = '{0}|{1}' -f $file, $info.LastWriteTimeUtc.Ticks
                    if ($seen.ContainsKey($sig)) { continue }
                    $seen[$sig] = $true
                    $threat = Test-FileThreat $file -UseVirusTotal
                    if (-not $threat -or $threat.level -notin 'RED', 'YELLOW') { continue }
                    Write-Log "Bekci: $($threat.level) $file"
                    if ($threat.level -eq 'RED') {
                        $threat = Resolve-RedFile $threat
                        Add-StatusFinding $threat
                        Raise-Red @($threat)
                    } else {
                        Add-StatusFinding $threat
                        # Sadece supheli dosyalar kisa bir bildirim alir; "taninmayan program" onerileri sessizce panele duser
                        if ((Get-FindingTab $threat) -eq 'threat') { Show-Toast $threat.title $threat.detail }
                    }
                    & $updateTray
                } catch { Write-Log "Bekci hatasi ($file): $_" }
            }
            $state.ticks++
            # Bekcinin yeni supheli davranis (Warn) bulgulari: anahtar basina bir kisa bildirim
            if ($state.ticks % 5 -eq 0) {
                try { [void](Invoke-GuardWarnNotices $guardNotify) } catch { Write-Log "Bekci uyari bildirimi hatasi: $_" }
            }
            if ($state.ticks % 30 -eq 0) { & $updateTray }
            if (((Get-Date) - $state.lastDaily).TotalHours -ge 24) {
                $state.lastDaily = Get-Date
                [void](Start-ScanProcess)
            }
        } finally { $state.busy = $false }
    })

    & $updateTray
    $tray.Visible = $true
    $tray.ShowBalloonTip(4000, 'Cortmed Security aktif', 'Bilgisayarınız gerçek zamanlı olarak korunuyor.', 'Info')
    $timer.Start()
    [Windows.Forms.Application]::Run()
    $timer.Stop(); $tray.Visible = $false; $tray.Dispose()
    if ($guard.client) { try { $guard.client.Dispose() } catch { } }
    foreach ($w in $watchers) { $w.Dispose() }
    $mutex.ReleaseMutex()
}

# ------------------------------------------------------------------ tema

Add-Type -AssemblyName System.Windows.Forms, System.Drawing

# Logodaki lacivert / camgobegi renkler
$UiBg = [Drawing.Color]::FromArgb(11, 21, 38)
$UiSurface = [Drawing.Color]::FromArgb(19, 34, 58)
$UiSurface2 = [Drawing.Color]::FromArgb(27, 46, 75)
$UiAccent = [Drawing.Color]::FromArgb(41, 182, 246)
$UiText = [Drawing.Color]::FromArgb(241, 245, 251)
$UiMuted = [Drawing.Color]::FromArgb(147, 164, 189)
$UiLevel = @{
    RED    = [Drawing.Color]::FromArgb(239, 68, 68)
    YELLOW = [Drawing.Color]::FromArgb(245, 165, 36)
    OK     = [Drawing.Color]::FromArgb(34, 197, 94)
    NONE   = [Drawing.Color]::FromArgb(147, 164, 189)
}

# Pencere cercevesi (Windows 10/11): koyu baslik cubugu ve yuvarlak koseler. Hata olursa sessizce atlanir (C# 5).
try {
    if (-not ('CortmedUi.Dwm' -as [type])) {
        Add-Type -TypeDefinition @'
using System;
using System.Runtime.InteropServices;
namespace CortmedUi {
    public static class Dwm {
        [DllImport("dwmapi.dll")]
        private static extern int DwmSetWindowAttribute(IntPtr hwnd, int attr, ref int value, int size);
        public static void Apply(IntPtr hwnd) {
            try {
                int on = 1;
                if (DwmSetWindowAttribute(hwnd, 20, ref on, 4) != 0) { DwmSetWindowAttribute(hwnd, 19, ref on, 4); }
                int round = 2;
                DwmSetWindowAttribute(hwnd, 33, ref round, 4);
            } catch (Exception) { }
        }
    }
}
'@
    }
} catch { }

# Koyu sag tik menusu renkleri (tema renklerinden kurulur)
try {
    if (-not ('CortmedUi.DarkColors' -as [type])) {
        Add-Type -ReferencedAssemblies System.Windows.Forms, System.Drawing -TypeDefinition @'
using System.Drawing;
using System.Windows.Forms;
namespace CortmedUi {
    public class DarkColors : ProfessionalColorTable {
        private Color bg;
        private Color hover;
        private Color border;
        public DarkColors(Color bg, Color hover, Color border) {
            this.bg = bg; this.hover = hover; this.border = border;
            this.UseSystemColors = false;
        }
        public override Color ToolStripDropDownBackground { get { return bg; } }
        public override Color ImageMarginGradientBegin { get { return bg; } }
        public override Color ImageMarginGradientMiddle { get { return bg; } }
        public override Color ImageMarginGradientEnd { get { return bg; } }
        public override Color MenuItemSelected { get { return hover; } }
        public override Color MenuItemSelectedGradientBegin { get { return hover; } }
        public override Color MenuItemSelectedGradientEnd { get { return hover; } }
        public override Color MenuItemPressedGradientBegin { get { return hover; } }
        public override Color MenuItemPressedGradientMiddle { get { return hover; } }
        public override Color MenuItemPressedGradientEnd { get { return hover; } }
        public override Color MenuItemBorder { get { return hover; } }
        public override Color MenuBorder { get { return border; } }
        public override Color SeparatorDark { get { return border; } }
        public override Color SeparatorLight { get { return bg; } }
    }
}
'@
    }
} catch { }

function Set-WindowChrome($form) {
    $form.Add_HandleCreated({ param($s, $e) try { [CortmedUi.Dwm]::Apply($s.Handle) } catch { } })
}

# Kalkan 100x120 birimlik bir yolda cizilir; Draw-Shield istenen boyuta olceklendirir
function New-ShieldPath {
    $p = New-Object Drawing.Drawing2D.GraphicsPath
    $p.AddBezier(0, 16, 20, 16, 36, 10, 50, 0)
    $p.AddBezier(50, 0, 64, 10, 80, 16, 100, 16)
    $p.AddLine(100, 16, 100, 62)
    $p.AddBezier(100, 62, 100, 90, 78, 108, 50, 120)
    $p.AddBezier(50, 120, 22, 108, 0, 90, 0, 62)
    $p.CloseFigure()
    return $p
}

# $symbol: check | alert | cross | dots
function Draw-Shield($g, [single]$x, [single]$y, [single]$h, [Drawing.Color]$c, [string]$symbol) {
    $g.SmoothingMode = 'AntiAlias'
    $s = $h / 120
    $g.TranslateTransform($x, $y); $g.ScaleTransform($s, $s)
    $path = New-ShieldPath
    $light = [Drawing.Color]::FromArgb(255, [math]::Min(255, $c.R + 32), [math]::Min(255, $c.G + 32), [math]::Min(255, $c.B + 32))
    $rect = New-Object Drawing.RectangleF(0, 0, 100, 120)
    $br = New-Object Drawing.Drawing2D.LinearGradientBrush($rect, $light, $c, [single]75)
    $g.FillPath($br, $path)
    $edge = New-Object Drawing.Pen ([Drawing.Color]::FromArgb(90, 255, 255, 255)), 2.5
    $g.DrawPath($edge, $path)
    $pen = New-Object Drawing.Pen ([Drawing.Color]::White), 10
    $pen.StartCap = 'Round'; $pen.EndCap = 'Round'; $pen.LineJoin = 'Round'
    $white = New-Object Drawing.SolidBrush ([Drawing.Color]::White)
    switch ($symbol) {
        'check' { $g.DrawLines($pen, [Drawing.PointF[]]@((New-Object Drawing.PointF(29, 62)), (New-Object Drawing.PointF(45, 78)), (New-Object Drawing.PointF(72, 44)))) }
        'alert' {
            $g.DrawLine($pen, 50, 32, 50, 66)
            $g.FillEllipse($white, 43, 78, 14, 14)
        }
        'cross' {
            $g.DrawLine($pen, 33, 45, 67, 79)
            $g.DrawLine($pen, 67, 45, 33, 79)
        }
        default {
            foreach ($dx in 28, 50, 72) { $g.FillEllipse($white, ($dx - 6), 54, 12, 12) }
        }
    }
    $g.ResetTransform()
    $white.Dispose(); $pen.Dispose(); $edge.Dispose(); $br.Dispose(); $path.Dispose()
}

# Uyari ucgeni (soru penceresi) yuvarlak koseli, icinde unlem
function New-WarnBitmap([int]$size) {
    $bmp = New-Object Drawing.Bitmap $size, $size
    $g = [Drawing.Graphics]::FromImage($bmp)
    $g.SmoothingMode = 'AntiAlias'
    $k = $size / 100.0
    $g.ScaleTransform($k, $k)
    $path = New-Object Drawing.Drawing2D.GraphicsPath
    $pts = [Drawing.PointF[]]@((New-Object Drawing.PointF(50, 8)), (New-Object Drawing.PointF(94, 86)), (New-Object Drawing.PointF(6, 86)))
    $path.AddPolygon($pts)
    $br = New-Object Drawing.Drawing2D.LinearGradientBrush((New-Object Drawing.RectangleF(0, 0, 100, 100)), [Drawing.Color]::FromArgb(255, 252, 191, 73), $UiLevel.YELLOW, [single]90)
    $pen = New-Object Drawing.Pen $UiLevel.YELLOW, 12
    $pen.LineJoin = 'Round'
    $g.DrawPath($pen, $path)
    $g.FillPath($br, $path)
    $dark = [Drawing.Color]::FromArgb(60, 38, 4)
    $pen2 = New-Object Drawing.Pen $dark, 9
    $pen2.StartCap = 'Round'; $pen2.EndCap = 'Round'
    $g.DrawLine($pen2, 50, 36, 50, 64)
    $g.FillEllipse((New-Object Drawing.SolidBrush $dark), 44.5, 69, 11, 11)
    $g.Dispose(); $path.Dispose(); $br.Dispose(); $pen.Dispose(); $pen2.Dispose()
    return $bmp
}

# Sag tik menusu: koyu ve duzgun (tema renkleri). $kind: open | scan | stop
function New-MenuGlyph([string]$kind) {
    $bmp = New-Object Drawing.Bitmap 16, 16
    $g = [Drawing.Graphics]::FromImage($bmp)
    $g.SmoothingMode = 'AntiAlias'
    switch ($kind) {
        'open' { Draw-Shield $g 2 0 16 $UiAccent 'check' }
        'scan' {
            $pen = New-Object Drawing.Pen $UiAccent, 2
            $pen.EndCap = 'Round'
            $g.DrawEllipse($pen, 2, 2, 8, 8); $g.DrawLine($pen, 9, 9, 13, 13)
            $pen.Dispose()
        }
        'stop' {
            $b = New-Object Drawing.SolidBrush $UiLevel.RED
            $g.FillRectangle($b, 3, 3, 10, 10); $b.Dispose()
        }
    }
    $g.Dispose()
    return $bmp
}

function Set-DarkMenuStyle($menu) {
    $menu.BackColor = $UiSurface; $menu.ForeColor = $UiText
    try {
        $ct = New-Object CortmedUi.DarkColors($UiSurface, $UiSurface2, [Drawing.Color]::FromArgb(48, 72, 108))
        $r = New-Object Windows.Forms.ToolStripProfessionalRenderer($ct)
        $r.RoundedEdges = $false
        $menu.Renderer = $r
    } catch { }
    foreach ($it in $menu.Items) { $it.ForeColor = $UiText }
}

function Get-CortmedIcon {
    $p = Join-Path $Root 'cortmed.ico'
    if (Test-Path $p) { try { return New-Object Drawing.Icon (New-Object IO.MemoryStream (, [IO.File]::ReadAllBytes($p))) } catch { } }
    return $null
}

function Get-CortmedLogo {
    $p = Join-Path $Root 'cortmed-logo.png'
    if (Test-Path $p) { try { return [Drawing.Image]::FromStream((New-Object IO.MemoryStream (, [IO.File]::ReadAllBytes($p)))) } catch { } }
    return $null
}

function New-Font([float]$size, [string]$style = 'Regular', [string]$family = 'Segoe UI') {
    if ($style -eq 'Bold' -and $family -eq 'Segoe UI') { $family = 'Segoe UI Semibold'; $style = 'Regular' }
    return New-Object Drawing.Font($family, $size, [Drawing.FontStyle]$style)
}

function New-Label([string]$text, [int]$x, [int]$y, $color = $UiText, $font = $null, [int]$maxWidth = 0) {
    $l = New-Object Windows.Forms.Label
    $l.Text = $text; $l.AutoSize = $true; $l.ForeColor = $color; $l.BackColor = [Drawing.Color]::Transparent
    $l.Location = New-Object Drawing.Point($x, $y)
    if ($font) { $l.Font = $font }
    if ($maxWidth) { $l.MaximumSize = New-Object Drawing.Size($maxWidth, 0) }
    return $l
}

function New-FlatButton([string]$text, [bool]$primary = $false, [string]$style = '') {
    $b = New-Object Windows.Forms.Button
    $b.Text = $text; $b.AutoSize = $true; $b.Height = 40
    $b.FlatStyle = 'Flat'; $b.Cursor = 'Hand'
    $b.Padding = New-Object Windows.Forms.Padding(12, 0, 12, 0)
    $b.Margin = New-Object Windows.Forms.Padding(0, 0, 10, 0)
    $b.Font = New-Font 10 'Bold'
    if ($style -eq 'danger') {
        # Kirmizi ana dugme (guvenli secenek: programi kapat)
        $b.BackColor = [Drawing.Color]::FromArgb(220, 38, 38); $b.ForeColor = [Drawing.Color]::White
        $b.FlatAppearance.BorderSize = 0
        $b.FlatAppearance.MouseOverBackColor = [Drawing.Color]::FromArgb(239, 68, 68)
    } elseif ($style -eq 'muted') {
        $b.BackColor = [Drawing.Color]::FromArgb(52, 62, 80); $b.ForeColor = [Drawing.Color]::FromArgb(208, 215, 226)
        $b.FlatAppearance.BorderSize = 0
        $b.FlatAppearance.MouseOverBackColor = [Drawing.Color]::FromArgb(66, 78, 100)
    } elseif ($style -eq 'link') {
        $b.BackColor = $UiBg; $b.ForeColor = $UiAccent
        $b.Font = New-Object Drawing.Font('Segoe UI Semibold', 10, [Drawing.FontStyle]::Underline)
        $b.FlatAppearance.BorderSize = 0
        $b.FlatAppearance.MouseOverBackColor = $UiSurface
    } elseif ($primary) {
        $b.BackColor = $UiAccent; $b.ForeColor = [Drawing.Color]::FromArgb(6, 20, 40)
        $b.FlatAppearance.BorderSize = 0
        $b.FlatAppearance.MouseOverBackColor = [Drawing.Color]::FromArgb(79, 195, 247)
    } else {
        $b.BackColor = $UiSurface2; $b.ForeColor = $UiText
        $b.FlatAppearance.BorderColor = [Drawing.Color]::FromArgb(48, 72, 108)
        $b.FlatAppearance.MouseOverBackColor = [Drawing.Color]::FromArgb(36, 60, 96)
    }
    return $b
}

function New-DarkForm([string]$title, [int]$w, [int]$h) {
    $f = New-Object Windows.Forms.Form
    $f.Text = $title
    $f.Size = New-Object Drawing.Size($w, $h)
    $f.StartPosition = 'CenterParent'
    $f.Font = New-Font 10
    $f.BackColor = $UiBg; $f.ForeColor = $UiText
    $icon = Get-CortmedIcon; if ($icon) { $f.Icon = $icon }
    Set-WindowChrome $f
    return $f
}

# Ust marka bandi: logo + CORTMED / SECURITY + sagda koruma durumu
function New-BrandBar {
    $bar = New-Object Windows.Forms.Panel
    $bar.Dock = 'Top'; $bar.Height = 68; $bar.BackColor = [Drawing.Color]::FromArgb(7, 16, 30)
    $logo = Get-CortmedLogo
    if ($logo) {
        $pic = New-Object Windows.Forms.PictureBox
        $pic.Image = $logo; $pic.SizeMode = 'Zoom'
        $pic.Size = New-Object Drawing.Size(46, 46); $pic.Location = New-Object Drawing.Point(18, 11)
        $bar.Controls.Add($pic)
    }
    $bar.Controls.Add((New-Label 'CORTMED' 72 8 $UiText (New-Font 17 'Bold')))
    $bar.Controls.Add((New-Label 'S E C U R I T Y' 75 40 $UiAccent (New-Font 8.5 'Bold')))
    return $bar
}

# ------------------------------------------------------------------ kart listesi

# "3 dakika önce", "dün" gibi sade bir zaman anlatimi
function Get-RelativeTime($t) {
    if (-not $t) { return 'henüz yapılmadı' }
    $d = (Get-Date) - [datetime]$t
    if ($d.TotalMinutes -lt 2) { return 'az önce' }
    if ($d.TotalMinutes -lt 60) { return '{0} dakika önce' -f [int]$d.TotalMinutes }
    if ($d.TotalHours -lt 24) { return '{0} saat önce' -f [int]$d.TotalHours }
    if ($d.TotalHours -lt 48) { return 'dün' }
    if ($d.TotalDays -lt 14) { return '{0} gün önce' -f [int]$d.TotalDays }
    return '{0:dd.MM.yyyy}' -f [datetime]$t
}

function New-RoundRegion([int]$w, [int]$h, [int]$r) {
    $p = New-Object Drawing.Drawing2D.GraphicsPath
    $d = $r * 2
    $p.AddArc(0, 0, $d, $d, 180, 90); $p.AddArc(($w - $d), 0, $d, $d, 270, 90)
    $p.AddArc(($w - $d), ($h - $d), $d, $d, 0, 90); $p.AddArc(0, ($h - $d), $d, $d, 90, 90)
    $p.CloseFigure()
    $reg = New-Object Drawing.Region $p
    $p.Dispose()
    return $reg
}

# Renkli seviye noktasi (halkali)
function New-LevelDot([Drawing.Color]$c) {
    $d = New-Object Windows.Forms.Panel
    $d.Size = New-Object Drawing.Size(28, 28); $d.BackColor = [Drawing.Color]::Transparent
    $d.Tag = $c
    $d.Add_Paint({
        param($s, $e)
        $g = $e.Graphics; $g.SmoothingMode = 'AntiAlias'
        $col = [Drawing.Color]$s.Tag
        $halo = New-Object Drawing.SolidBrush ([Drawing.Color]::FromArgb(60, $col))
        $dot = New-Object Drawing.SolidBrush $col
        $g.FillEllipse($halo, 0, 0, 27, 27); $g.FillEllipse($dot, 7, 7, 13, 13)
        $halo.Dispose(); $dot.Dispose()
    })
    return $d
}

# Kartin ustune gelince hafifce acilir (cocuk denetimlerde de calisir)
function Add-CardHover($card) {
    $enter = { param($s, $e) $c = $s; while ($c -and $c.Name -ne 'card') { $c = $c.Parent }; if ($c) { $c.BackColor = $UiSurface2 } }
    $leave = {
        param($s, $e)
        $c = $s; while ($c -and $c.Name -ne 'card') { $c = $c.Parent }
        if ($c -and -not $c.ClientRectangle.Contains($c.PointToClient([Windows.Forms.Cursor]::Position))) { $c.BackColor = $UiSurface }
    }
    foreach ($ctl in (@($card) + @($card.Controls))) {
        $ctl.Add_MouseEnter($enter); $ctl.Add_MouseLeave($leave)
    }
}

# Genel kart: solda $lead (nokta ya da simge), kalin baslik, soluk ayrinti, sagda dugmeler (soldan saga sirayla verilir)
function New-Card([int]$w, [int]$h, $lead, [string]$title, [string]$detail, $buttons, [int]$detailLines = 1, $tips = $null) {
    $card = New-Object Windows.Forms.Panel
    $card.Name = 'card'; $card.Size = New-Object Drawing.Size($w, $h); $card.BackColor = $UiSurface
    $card.Margin = New-Object Windows.Forms.Padding(0, 0, 0, 10)
    $x = 18
    if ($lead) {
        $lead.Location = New-Object Drawing.Point(18, [int](($h - $lead.Height) / 2))
        $card.Controls.Add($lead); $x = 18 + $lead.Width + 14
    }
    $bx = $w - 16
    $btnList = @($buttons | Where-Object { $_ })
    for ($i = $btnList.Count - 1; $i -ge 0; $i--) {
        $b = $btnList[$i]
        $b.AutoSize = $false; $b.Height = 36
        $b.Width = [math]::Max(110, [Windows.Forms.TextRenderer]::MeasureText($b.Text, $b.Font).Width + 36)
        $bx -= $b.Width
        $b.Location = New-Object Drawing.Point($bx, [int](($h - $b.Height) / 2))
        $card.Controls.Add($b); $b.Anchor = 'Top, Right'
        $bx -= 10
    }
    $textW = [math]::Max(80, $bx - 6 - $x)
    $detH = 19 * $detailLines + 2
    $top = [int](($h - (24 + 2 + $detH)) / 2)
    $ttl = New-Object Windows.Forms.Label
    $ttl.AutoSize = $false; $ttl.AutoEllipsis = $true; $ttl.Text = $title; $ttl.Font = New-Font 11 'Bold'
    $ttl.ForeColor = $UiText; $ttl.BackColor = [Drawing.Color]::Transparent
    $ttl.Location = New-Object Drawing.Point($x, $top); $ttl.Size = New-Object Drawing.Size($textW, 24)
    $det = New-Object Windows.Forms.Label
    $det.AutoSize = $false; $det.AutoEllipsis = $true; $det.Text = $detail; $det.Font = New-Font 9.5
    $det.ForeColor = $UiMuted; $det.BackColor = [Drawing.Color]::Transparent
    $det.Location = New-Object Drawing.Point($x, ($top + 26)); $det.Size = New-Object Drawing.Size($textW, $detH)
    $card.Controls.Add($ttl); $card.Controls.Add($det)
    $ttl.Anchor = 'Top, Left, Right'; $det.Anchor = 'Top, Left, Right'
    if ($tips -and $detail) { $tips.SetToolTip($ttl, $detail); $tips.SetToolTip($det, $detail) }
    Add-CardHover $card
    $card.Add_Resize({
        param($s, $e)
        if ($s.Width -gt 20 -and $s.Height -gt 20) { $old = $s.Region; $s.Region = New-RoundRegion $s.Width $s.Height 8; if ($old) { $old.Dispose() } }
    })
    $card.Region = New-RoundRegion $w $h 8
    return $card
}

# Davranis bekcisi bulgusunun dosyasi karantinaya alinabilir mi (Ayrintilar penceresiyle ayni kosul)
function Test-CanQuarantine($finding) {
    return ([string]$finding.key -like 'behavior:*' -and $finding.path -and -not (Test-GuardSystemPath ([string]$finding.path)) -and
        (Test-Path -LiteralPath $finding.path -PathType Leaf))
}

# Onay sorar, dosyayi karantinaya alir. Basarili olursa $true.
function Confirm-QuarantineFinding($finding) {
    $a = [Windows.Forms.MessageBox]::Show(
        "Dosya, açılamayacağı Karantina klasörüne taşınacak:`n`n$($finding.path)`n`nProgram hâlâ çalışıyorsa önce kapatın. Devam edilsin mi?",
        'Karantinaya al', 'YesNo', 'Question')
    if ($a -ne 'Yes') { return $false }
    if (Invoke-Quarantine ([string]$finding.path)) {
        [Windows.Forms.MessageBox]::Show('Dosya karantinaya alındı.', 'Cortmed Security') | Out-Null
        return $true
    }
    [Windows.Forms.MessageBox]::Show('Dosya karantinaya alınamadı. Program hâlâ çalışıyor olabilir; bilgisayarı yeniden başlatıp tekrar deneyin.', 'Cortmed Security') | Out-Null
    return $false
}

# Bir bulgu = bir kart. $onDone: { param($card) } -> guvenilir isaretlenince ya da karantinaya alinca cagrilir.
function New-FindingCard($finding, [int]$w, $tips, [scriptblock]$onDone) {
    $levelKey = if ($UiLevel.ContainsKey([string]$finding.level)) { [string]$finding.level } else { 'NONE' }
    $detail = (([string]$finding.detail) -replace '\s+', ' ').Trim()
    $ctx = @{ finding = $finding; done = $onDone }
    $more = New-FlatButton 'Ayrıntılar' $true
    $more.Tag = $ctx
    $more.Add_Click({
        param($s, $e)
        $t = $s.Tag; $card = $s.Parent
        if (Show-Report $s.FindForm() $t.finding) { if ($t.done) { & $t.done $card } }
    })
    $buttons = @()
    if (Test-CanQuarantine $finding) {
        $quar = New-FlatButton 'Karantinaya al'
        $quar.Tag = $ctx
        $quar.Add_Click({
            param($s, $e)
            $t = $s.Tag; $card = $s.Parent
            if (Confirm-QuarantineFinding $t.finding) {
                if ($card.Parent) { $card.Parent.Tag = $null }
                if ($t.done) { & $t.done $card }
            }
        })
        $buttons += $quar
    }
    $buttons += $more
    return (New-Card $w 74 (New-LevelDot $UiLevel[$levelKey]) ([string]$finding.title) $detail $buttons 1 $tips)
}

# Onerilerimiz kategorisi (Windows korumalari, guncellemeler...) = bir kart + tek eylem dugmesi
function New-AdviceCard($grp, [int]$w, $tips, [scriptblock]$onAction) {
    $c = $grp.cat
    $ico = New-Object Windows.Forms.Label
    $ico.AutoSize = $false; $ico.Size = New-Object Drawing.Size(46, 46); $ico.Text = $c.icon
    $ico.TextAlign = 'MiddleCenter'; $ico.Font = New-Font 17 'Regular' 'Segoe UI Emoji'
    $ico.ForeColor = $UiAccent; $ico.BackColor = $UiSurface2
    $btn = New-FlatButton $c.button $true
    $btn.Tag = @{ grp = $grp; run = $onAction }
    $btn.Add_Click({ param($s, $e) $t = $s.Tag; & $t.run $t.grp })
    return (New-Card $w 96 $ico ([string]$c.title) ($c.text -f $grp.items.Count) @($btn) 2 $tips)
}

# Bolum basligi (Durdurulan programlar gibi)
function New-SectionHeader([string]$title, [string]$sub, [int]$w) {
    $h = New-Object Windows.Forms.Panel
    $h.Name = 'header'; $h.BackColor = $UiBg
    $h.Size = New-Object Drawing.Size($w, $(if ($sub) { 58 } else { 32 }))
    $h.Margin = New-Object Windows.Forms.Padding(0, 6, 0, 4)
    $t = New-Label $title 2 2 $UiAccent (New-Font 11.5 'Bold')
    $h.Controls.Add($t)
    if ($sub) {
        $s = New-Label $sub 2 28 $UiMuted (New-Font 9.5) ($w - 20)
        $h.Controls.Add($s)
    }
    return $h
}

function Get-CardWidth($flow) { return [math]::Max(300, $flow.ClientSize.Width - 22) }

function Set-FlowWidths($flow) {
    $w = Get-CardWidth $flow
    foreach ($c in $flow.Controls) { if (($c.Name -eq 'card' -or $c.Name -eq 'header') -and $c.Width -ne $w) { $c.Width = $w } }
}

# Kaydirilabilir kart akisi
function New-CardFlow {
    $flow = New-Object Windows.Forms.FlowLayoutPanel
    $flow.Dock = 'Fill'; $flow.FlowDirection = 'TopDown'; $flow.WrapContents = $false
    $flow.AutoScroll = $true; $flow.BackColor = $UiBg
    $flow.Padding = New-Object Windows.Forms.Padding(0, 4, 0, 8)
    $flow.Add_Resize({ param($s, $e) Set-FlowWidths $s })
    return $flow
}

function Clear-Flow($flow) {
    foreach ($c in @($flow.Controls)) { $c.Dispose() }
}

# Bulgulari kart olarak akisin sonuna ekler (once Clear-Flow / SuspendLayout cagiran yapar)
function Add-FindingCards($flow, $findings, $tips, [scriptblock]$onDone) {
    $w = Get-CardWidth $flow
    foreach ($f in @($findings)) { $flow.Controls.Add((New-FindingCard $f $w $tips $onDone)) }
}
# Dosya raporu penceresi. Kullanici dosyaya guvenirse $true dondurur.
function Show-Report($owner, $finding) {
    # Dugme olaylari ShowDialog sirasinda bu kapsamda calisir: $f, $finding ve $result burada tanimli olmali
    $f = New-ReportForm $finding
    $result = $f.Tag
    [void]$f.ShowDialog($owner)
    return $result.trusted
}

# Ayrintilar penceresini kurar, gostermez (dugmeler Show-Report kapsaminda calisir). Tag.trusted: kullanici
# "bu dosyaya guveniyorum" dedi.
function New-ReportForm($finding) {
    $levelKey = if ($UiLevel.ContainsKey([string]$finding.level)) { [string]$finding.level } else { 'NONE' }
    $f = New-DarkForm 'Cortmed Security - Ayrıntılar' 760 560
    $head = New-Object Windows.Forms.Label
    $head.Dock = 'Top'; $head.Height = 54; $head.Padding = New-Object Windows.Forms.Padding(16, 0, 0, 0)
    $head.TextAlign = 'MiddleLeft'; $head.Text = $finding.title
    $head.Font = New-Font 13 'Bold'
    $head.ForeColor = [Drawing.Color]::White; $head.BackColor = $UiLevel[$levelKey]
    $wrap = New-Object Windows.Forms.Panel
    $wrap.Dock = 'Fill'; $wrap.Padding = New-Object Windows.Forms.Padding(16, 12, 16, 4); $wrap.BackColor = $UiBg
    $box = New-Object Windows.Forms.TextBox
    $box.Multiline = $true; $box.ReadOnly = $true; $box.ScrollBars = 'Vertical'; $box.Dock = 'Fill'
    $box.BackColor = $UiSurface; $box.ForeColor = $UiText; $box.BorderStyle = 'None'
    $box.Font = New-Font 10.5
    $box.Text = if ($finding.report) { $finding.report } else { $finding.detail }
    $wrap.Controls.Add($box)
    $bar = New-Object Windows.Forms.FlowLayoutPanel
    $bar.Dock = 'Bottom'; $bar.Height = 62; $bar.Padding = New-Object Windows.Forms.Padding(16, 10, 16, 10); $bar.BackColor = $UiBg
    $result = @{ trusted = $false }
    $f.Tag = $result
    if ($finding.path -and (Test-Path -LiteralPath $finding.path)) {
        $open = New-FlatButton 'Dosyanın klasörünü aç'
        $open.Add_Click({ Start-Process explorer.exe "/select,`"$($finding.path)`"" })
        [void]$bar.Controls.Add($open)
    }
    # Davranis bekcisi bulgusu (durdurulmayan ya da kapatilan program): dosyayi mevcut karantina islemiyle kaldir
    if (Test-CanQuarantine $finding) {
        $quar = New-FlatButton 'Karantinaya al'
        $quar.Add_Click({ if (Confirm-QuarantineFinding $finding) { $f.Close() } })
        [void]$bar.Controls.Add($quar)
    }
    if ([string]$finding.key -like 'file:*' -and $finding.level -in 'RED', 'YELLOW') {
        $trust = New-FlatButton 'Bu dosyaya güveniyorum'
        $trust.Add_Click({
            $a = [Windows.Forms.MessageBox]::Show(
                "Cortmed bu dosya için bir daha uyarı vermeyecek.`n`nDosyayı kendiniz indirdiyseniz ve nereden geldiğini biliyorsanız devam edin.",
                'Bu dosyaya güveniyor musunuz?', 'YesNo', 'Question')
            if ($a -eq 'Yes') { Set-FileTrusted $finding; $result.trusted = $true; $f.Close() }
        })
        [void]$bar.Controls.Add($trust)
    }
    $close = New-FlatButton 'Kapat' $true
    $close.Add_Click({ $f.Close() })
    [void]$bar.Controls.Add($close)
    $f.Controls.AddRange(@($wrap, $bar, $head))
    $box.Select(0, 0)
    return $f
}

function Show-FindingList($owner, [string]$title, $findings) {
    $f = New-DarkForm "Cortmed Security - $title" 900 560
    $tips = New-Object Windows.Forms.ToolTip
    $wrap = New-Object Windows.Forms.Panel
    $wrap.Dock = 'Fill'; $wrap.Padding = New-Object Windows.Forms.Padding(16, 8, 16, 8); $wrap.BackColor = $UiBg
    $flow = New-CardFlow
    # Guvenilir isaretlenen ya da karantinaya alinan bulgu listeden kalkar
    $onDone = { param($card) if ($card -and $card.Parent) { $card.Parent.Controls.Remove($card); $card.Dispose() } }
    $flow.SuspendLayout()
    Add-FindingCards $flow $findings $tips $onDone
    $flow.ResumeLayout()
    $wrap.Controls.Add($flow)
    $hint = New-Object Windows.Forms.Label
    $hint.Dock = 'Top'; $hint.Height = 34; $hint.TextAlign = 'MiddleLeft'; $hint.Padding = New-Object Windows.Forms.Padding(18, 0, 0, 0)
    $hint.Text = 'Ayrıntı için ilgili kartın "Ayrıntılar" düğmesine tıklayın.'
    $hint.ForeColor = $UiMuted; $hint.Font = New-Font 9
    $f.Controls.AddRange(@($wrap, $hint))
    [void]$f.ShowDialog($owner)
}

# ------------------------------------------------------------------ davranis bekcisi sorusu

# Soru kimligine gore: acik pencereler, verilen kararlar, geri cekilenler, ilk gorulme zamanlari.
# connected/connectedAt/resent: yeniden baglantidan sonra hizmetin yeniden gondermedigi sorulari bulmak icin.
function New-GuardState {
    return @{ open = @{}; answered = @{}; gone = @{}; firstSeen = @{}; reminded = @{}; prompts = @{}
        connected = $false; connectedAt = $null; reconciled = $true; resent = @{}; killPaths = @{} }
}

# "Bu program durdurulsun mu" penceresini kurar, gostermez.
# $answer: { param($id, $decision) } -> $true: cevap hizmete yazildi; baska her sey: yazilamadi, pencere acik kalir
function New-GuardPromptForm($prompt, [scriptblock]$answer, $state = $null) {
    $name = [string]$prompt.program
    if (-not $name -and $prompt.path) { $name = Split-Path ([string]$prompt.path) -Leaf }
    if (-not $name) { $name = 'bilinmeyen program' }
    $publisher = if ([string]$prompt.publisher) { [string]$prompt.publisher } else { 'bilinmiyor (imzasız)' }
    $reasons = @($prompt.reasons | Where-Object { $_ } | ForEach-Object { [string]$_ })

    $f = New-DarkForm "Cortmed şüpheli bir programı durdurdu: $name" 640 580
    $f.StartPosition = 'CenterScreen'; $f.TopMost = $true
    $f.FormBorderStyle = 'FixedDialog'; $f.MaximizeBox = $false; $f.MinimizeBox = $false
    $f.Tag = @{ id = [string]$prompt.id; path = [string]$prompt.path; answer = $answer; state = $state; decision = $null; result = $null }

    # Ust bant: buyuk uyari simgesi, baslik ve ne oldugu
    $head = New-Object Windows.Forms.Panel
    $head.Dock = 'Top'; $head.Height = 112; $head.BackColor = [Drawing.Color]::FromArgb(58, 24, 32)
    $warn = New-Object Windows.Forms.PictureBox
    $warn.Image = New-WarnBitmap 72; $warn.SizeMode = 'CenterImage'; $warn.BackColor = [Drawing.Color]::Transparent
    $warn.Size = New-Object Drawing.Size(80, 80); $warn.Location = New-Object Drawing.Point(18, 16)
    $head.Controls.Add($warn)
    $head.Controls.Add((New-Label 'Şüpheli bir program durduruldu' 108 16 ([Drawing.Color]::White) (New-Font 16 'Bold')))
    $head.Controls.Add((New-Label 'Cortmed bu programı ve başlattığı programları dondurdu. Siz karar verene kadar hiçbir şey yapamaz.' 110 54 ([Drawing.Color]::FromArgb(236, 214, 218)) (New-Font 10) 490))

    $body = New-Object Windows.Forms.FlowLayoutPanel
    $body.Dock = 'Fill'; $body.FlowDirection = 'TopDown'; $body.WrapContents = $false; $body.AutoScroll = $true
    $body.Padding = New-Object Windows.Forms.Padding(18, 16, 18, 4); $body.BackColor = $UiBg

    # Programin kendi simgesi, adi, yayincisi ve yolu
    $progBmp = $null
    try {
        if ($prompt.path -and (Test-Path -LiteralPath ([string]$prompt.path) -PathType Leaf)) {
            $ic = [Drawing.Icon]::ExtractAssociatedIcon([string]$prompt.path)
            if ($ic) { $progBmp = $ic.ToBitmap() }
        }
    } catch { }
    if (-not $progBmp) { try { $progBmp = [Drawing.SystemIcons]::Application.ToBitmap() } catch { } }
    $card = New-Object Windows.Forms.Panel
    $card.Size = New-Object Drawing.Size(570, 84); $card.BackColor = $UiSurface
    $card.Margin = New-Object Windows.Forms.Padding(0, 0, 0, 14)
    if ($progBmp) {
        $pic = New-Object Windows.Forms.PictureBox
        $pic.Image = $progBmp; $pic.SizeMode = 'CenterImage'; $pic.BackColor = $UiSurface2
        $pic.Size = New-Object Drawing.Size(52, 52); $pic.Location = New-Object Drawing.Point(16, 16)
        $card.Controls.Add($pic)
    }
    foreach ($row in @(
            @{ t = $name; y = 10; c = $UiText; f = (New-Font 12 'Bold') }
            @{ t = "Yayıncı: $publisher"; y = 38; c = $UiMuted; f = (New-Font 9.5) }
            @{ t = [string]$prompt.path; y = 58; c = $UiMuted; f = (New-Font 9) })) {
        $l = New-Object Windows.Forms.Label
        $l.AutoSize = $false; $l.AutoEllipsis = $true; $l.Text = $row.t; $l.Font = $row.f; $l.ForeColor = $row.c
        $l.BackColor = [Drawing.Color]::Transparent
        $l.Location = New-Object Drawing.Point(80, $row.y); $l.Size = New-Object Drawing.Size(478, 22)
        $card.Controls.Add($l)
    }
    [void]$body.Controls.Add($card)

    $why = New-Label 'Neden durduruldu:' 0 0 $UiText (New-Font 10.5 'Bold') 570
    $why.Margin = New-Object Windows.Forms.Padding(0, 0, 0, 8)
    [void]$body.Controls.Add($why)
    foreach ($r in $reasons) {
        $row = New-Object Windows.Forms.FlowLayoutPanel
        $row.FlowDirection = 'LeftToRight'; $row.WrapContents = $false; $row.AutoSize = $true; $row.AutoSizeMode = 'GrowAndShrink'
        $row.BackColor = $UiBg; $row.Margin = New-Object Windows.Forms.Padding(0, 0, 0, 6)
        $bullet = New-Label '•' 0 0 $UiLevel.RED (New-Font 12 'Bold')
        $bullet.Margin = New-Object Windows.Forms.Padding(2, 0, 8, 0)
        $txt = New-Label $r 0 0 $UiText (New-Font 10) 520
        $txt.Margin = New-Object Windows.Forms.Padding(0, 3, 0, 0)
        $row.Controls.AddRange(@($bullet, $txt))
        [void]$body.Controls.Add($row)
    }

    $bar = New-Object Windows.Forms.FlowLayoutPanel
    $bar.Dock = 'Bottom'; $bar.Height = 74; $bar.Padding = New-Object Windows.Forms.Padding(18, 14, 16, 10); $bar.BackColor = $UiBg
    # Dugmeler kapanis degiskeni kullanmaz: bilgi formun ve dugmenin Tag'inde (pencere sonradan tiklanir)
    $onChoice = {
        param($sender, $e)
        $form = $sender.FindForm(); $t = $form.Tag
        if ($t.decision) { return }
        $r = & $t.answer $t.id ([string]$sender.Tag)
        if ($r -is [array]) { $r = $r[-1] }
        if (-not (($r -is [bool]) -and $r)) { return }
        $t.decision = [string]$sender.Tag; $t.result = $r
        # Karar saklanir: soru yeniden gelirse (cevap yolda kaybolduysa) ayni karar yeniden gonderilir
        if ($t.state) { $t.state.answered[$t.id] = $t.decision; $t.state.open.Remove($t.id); $t.state.prompts.Remove($t.id) }
        # Kapatma: hizmet "result ok=true" derse (program kapatildi) dosya ayara gore karantinaya alinir
        if ($t.state -and $t.state.killPaths -ne $null -and $t.decision -eq 'kill' -and $t.path) { $t.state.killPaths[$t.id] = $t.path }
        $form.Close()
    }
    $kill = New-FlatButton 'Programı kapat (önerilen)' $false 'danger'
    $kill.Height = 44
    $kill.Tag = 'kill'; $kill.Add_Click($onChoice)
    $allow = New-FlatButton 'İzin ver, devam etsin' $false 'muted'
    $allow.Height = 44
    $allow.Tag = 'allow'; $allow.Add_Click($onChoice)
    $more = New-FlatButton 'Ayrıntılar' $false 'link'
    $more.Height = 44; $more.Margin = New-Object Windows.Forms.Padding(0)
    $report = "Program: $([string]$prompt.path)`r`nYayıncı: $publisher`r`nDavranış puanı: $([string]$prompt.score)`r`n`r`nNedenler:`r`n" +
        (($reasons | ForEach-Object { "- $_" }) -join "`r`n")
    $more.Tag = [pscustomobject]@{ key = "guard:$($prompt.id)"; level = 'RED'; title = "Durdurulan program: $name"
        detail = ($reasons -join ' '); path = [string]$prompt.path; report = $report }
    $more.Add_Click({ param($sender, $e) [void](Show-Report $sender.FindForm() $sender.Tag) })
    $bar.Controls.AddRange(@($kill, $allow, $more))

    # Secim yapmadan kapatma: cevap gonderilmez, program donuk kalir
    $f.Add_FormClosed({ param($sender, $e) $t = $sender.Tag; if ($t.state) { $t.state.open.Remove($t.id) } })
    $f.Controls.AddRange(@($body, $bar, $head))
    return $f
}

# Soru artik yok (geri cekildi ya da hizmet tanimiyor): penceresi aciksa kapanir ve kisa not gosterilir.
# $notify: { param($title, $text, $sticky) }
function Close-GuardPrompt($state, [string]$id, [scriptblock]$notify) {
    $w = $state.open[$id]
    $wasOpen = $w -and -not $w.IsDisposed
    $state.gone[$id] = $true
    $state.open.Remove($id); $state.firstSeen.Remove($id); $state.prompts.Remove($id)
    if ($wasOpen) {
        $w.Close()
        if ($notify) { & $notify 'Cortmed Security' 'Bu program artık çalışmıyor; bir şey yapmanıza gerek yok.' $false }
    }
}

# Hizmetten gelen satiri "type" alanina gore isler:
#   ask: ayni kimlige ikinci pencere yok; daha once cevaplanan kimlik icin saklanan karar yeniden gonderilir
#   withdraw / result ok=false: soru artik yok; result ok=true: cevap ulasti; diger turler yok sayilir
#   result ok=true bir "kapat" cevabinin sonucuysa sorunun dosyasi $Quarantine'e verilir (varsayilan: otomatik
#   karantina ayari aciksa mevcut Invoke-Quarantine).
# Kurulan pencereyi dondurur (gosterilmezse -NoShow), aksi halde $null.
$DefaultGuardQuarantine = {
    param($path)
    if ((Get-Config).autoQuarantine -eq $true -and $path -and -not (Test-GuardSystemPath ([string]$path)) -and
        (Test-Path -LiteralPath $path -PathType Leaf)) { return (Invoke-Quarantine $path) }
    return $false
}
function Receive-GuardPrompt($state, [string]$json, [scriptblock]$answer, [scriptblock]$Notify = $null, $Now = $null, [switch]$NoShow,
    [scriptblock]$Quarantine = $null) {
    if (-not $Now) { $Now = Get-Date }
    $p = $null
    try { $p = $json | ConvertFrom-Json } catch { return $null }
    if (-not $p -or -not $p.PSObject.Properties['id'] -or -not [string]$p.id) { return $null }
    $id = [string]$p.id
    $type = if ($p.PSObject.Properties['type']) { [string]$p.type } else { '' }
    switch ($type) {
        'ask' {
            $state.resent[$id] = $true
            if ($state.answered.ContainsKey($id)) { [void](& $answer $id $state.answered[$id]); return $null }
            $state.gone.Remove($id)
            $old = $state.open[$id]
            if ($old -and -not $old.IsDisposed) { return $null }
            if (-not $state.firstSeen.ContainsKey($id)) { $state.firstSeen[$id] = $Now }
            $state.prompts[$id] = $json
            $f = New-GuardPromptForm $p $answer $state
            $state.open[$id] = $f
            if (-not $NoShow) { $f.Show(); $f.Activate() }
            return $f
        }
        'withdraw' { Close-GuardPrompt $state $id $Notify; return $null }
        'result' {
            $killPath = $null
            if ($state.killPaths -ne $null -and $state.killPaths.ContainsKey($id)) { $killPath = $state.killPaths[$id]; $state.killPaths.Remove($id) }
            if ($p.ok -eq $true) {
                $state.firstSeen.Remove($id); $state.prompts.Remove($id)
                if ($killPath) {
                    $q = if ($Quarantine) { $Quarantine } else { $DefaultGuardQuarantine }
                    $done = $false
                    try { $r = & $q $killPath; if ($r -is [array]) { $r = $r[-1] }; $done = ($r -is [bool]) -and $r } catch { }
                    if ($done -and $Notify) {
                        & $Notify 'Cortmed Security' "Program kapatıldı ve dosyası karantinaya alındı: $(Split-Path $killPath -Leaf)" $false
                    }
                }
            }
            else { Close-GuardPrompt $state $id $Notify }
            return $null
        }
    }
    return $null
}

function Show-GuardPrompt($state, [string]$promptJson, [scriptblock]$answer, [scriptblock]$Notify = $null) {
    return Receive-GuardPrompt $state $promptJson $answer -Notify $Notify
}

# 10 dakikadir cevapsiz sorular; her kimlik icin bir kez doner
function Get-GuardOverdue($state, [datetime]$now) {
    foreach ($id in @($state.firstSeen.Keys)) {
        if ($state.answered.ContainsKey($id) -or $state.reminded.ContainsKey($id) -or $state.gone.ContainsKey($id)) { continue }
        if (($now - $state.firstSeen[$id]).TotalMinutes -ge 10) { $state.reminded[$id] = $true; $id }
    }
}

# Bekci zamanlayicisinin bir tiki (Start-Watcher her saniye cagirir; testte sahte istemci ve saatle).
# Yeniden baglantidan 5 sn sonra hizmetin yeniden gondermedigi cevapsiz sorular geri cekilmis sayilir.
function Invoke-GuardTick($state, $client, [datetime]$now, [scriptblock]$answer, [scriptblock]$notify, [switch]$NoShow) {
    $connected = [bool]$client.Connected
    if ($connected -and -not $state.connected) { $state.connectedAt = $now; $state.resent = @{}; $state.reconciled = $false }
    $state.connected = $connected

    $pj = $null; $n = 0
    while ($n -lt 10 -and $client.TryDequeuePrompt([ref]$pj)) {
        $n++
        [void](Receive-GuardPrompt $state $pj $answer -Notify $notify -Now $now -NoShow:$NoShow)
    }

    if ($connected -and -not $state.reconciled -and ($now - $state.connectedAt).TotalSeconds -ge 5) {
        $state.reconciled = $true
        foreach ($id in @($state.firstSeen.Keys)) {
            if ($state.answered.ContainsKey($id) -or $state.resent.ContainsKey($id)) { continue }
            Close-GuardPrompt $state $id $notify
        }
    }

    # 10 dakika cevapsiz: kalici bildirim, pencere kapatildiysa yeniden ac
    foreach ($id in @(Get-GuardOverdue $state $now)) {
        $json = $state.prompts[$id]
        $name = ''
        try { $name = [string]($json | ConvertFrom-Json).program } catch { }
        $what = if ($name) { "Durdurduğumuz program ($name)" } else { 'Durdurduğumuz program' }
        if ($notify) { & $notify 'Cortmed kararınızı bekliyor' "$what hâlâ bekliyor. Açılan pencereden kapatmayı ya da izin vermeyi seçin." $true }
        if ($json) { [void](Receive-GuardPrompt $state $json $answer -Notify $notify -Now $now -NoShow:$NoShow) }
    }
}

# ------------------------------------------------------------------ ayarlar

$SettingsPageNames = @('Koruma', 'Davranış bekçisi', 'Veritabanı', 'Güvenilir dosyalar', 'Karantina', 'Gelişmiş', 'Hakkında')
$SettingsCardW = 610
$AboutUrl = 'https://github.com/cortmed/CortmedSecurity'

# Ek tarama motoru (ClamAV) kurulumunu arka planda baslatir
function Start-ClamInstall {
    if (Test-Path $LauncherExe) { [void](Start-Process $LauncherExe -ArgumentList '--mode', 'InstallClamAV') }
    else {
        [void](Start-Process powershell.exe -WindowStyle Hidden -ArgumentList @('-NoProfile', '-ExecutionPolicy', 'Bypass',
            '-File', ('"{0}"' -f (Join-Path $Root 'CortmedSecurity.ps1')), '-Mode', 'InstallClamAV'))
    }
}

# "Bekciyi ac / onar": onay sorar, UAC ile Install-Guard.ps1'i baslatir. Surec doner (reddedildiyse ya da yoksa $null).
function Start-GuardSetup {
    $svcExists = [bool](Get-Service CortmedGuard -ErrorAction SilentlyContinue)
    $cmdInfo = Get-GuardSetupCommand $svcExists
    if ($cmdInfo.missing) {
        [Windows.Forms.MessageBox]::Show('Davranış bekçisinin kurulum dosyaları bulunamadı. Cortmed Security''yi indirdiğiniz paketten yeniden kurup tekrar deneyin.', 'Cortmed Security') | Out-Null
        return $null
    }
    $setup = $cmdInfo.script
    $a = [Windows.Forms.MessageBox]::Show(
        "Davranış bekçisi açılacak. Şüpheli davranan bir programı çalışırken durdurur ve ne yapılacağını size sorar.`n`nWindows bir onay penceresi gösterecek. Devam edilsin mi?",
        'Davranış bekçisini açın', 'YesNo', 'Question')
    if ($a -ne 'Yes') { return $null }
    # Dogrudan yonetici olarak (UAC) baslatilir: onay reddedilirse Start-Process hata verir ve hicbir sey olmaz;
    # boylece cikis kodu yalnizca gercek kurulum sonucunu gosterir. 64 bit PowerShell (Program Files x86 olmasin).
    $psDir = if ([Environment]::Is64BitOperatingSystem -and -not [Environment]::Is64BitProcess) { Join-Path $env:windir 'Sysnative' } else { [Environment]::SystemDirectory }
    try {
        $proc = Start-Process (Join-Path $psDir 'WindowsPowerShell\v1.0\powershell.exe') -Verb RunAs -PassThru -ArgumentList @('-NoProfile', '-ExecutionPolicy', 'Bypass',
            '-File', ('"{0}"' -f $setup), '-Source', ('"{0}"' -f $cmdInfo.source), '-Elevated')
        # Tutamac hemen alinir; yoksa surec bitince ExitCode okunamaz
        if ($proc) { $null = $proc.Handle }
        return $proc
    } catch { return $null }
}

# Bekcinin izin verilen programlar listesi (yalniz hizmet yazar; tepsi sadece okur). Satirlar SHA-256 parmak izidir.
function Get-GuardAllowedList {
    $p = Join-Path $GuardDataDir 'allowed.txt'
    if (-not (Test-Path -LiteralPath $p)) { return @{ ok = $true; items = @() } }
    try {
        $items = @([IO.File]::ReadAllLines($p, [Text.Encoding]::UTF8) | ForEach-Object { $_.Trim() } |
            Where-Object { $_ -match '^[0-9a-fA-F]{64}$' } | Select-Object -Unique)
        return @{ ok = $true; items = $items }
    } catch { return @{ ok = $false; items = @() } }
}

# ---- ayarlar penceresi parcalari

function New-ToggleSwitch([bool]$on, [scriptblock]$onChange, [string]$name = '') {
    $t = New-Object Windows.Forms.Button
    $t.Name = 'toggle'; $t.Size = New-Object Drawing.Size(48, 26)
    $t.FlatStyle = 'Flat'; $t.FlatAppearance.BorderSize = 0; $t.TabStop = $true
    $t.BackColor = $UiSurface
    $t.FlatAppearance.MouseOverBackColor = $UiSurface; $t.FlatAppearance.MouseDownBackColor = $UiSurface
    $t.Cursor = 'Hand'; $t.AccessibleName = $name; $t.AccessibleRole = 'CheckButton'
    $t.Tag = @{ on = $on; change = $onChange }
    $t.Add_Paint({
        param($s, $e)
        $g = $e.Graphics; $g.SmoothingMode = 'AntiAlias'
        $on = [bool]$s.Tag.on
        $w = $s.Width - 2; $h = $s.Height - 2
        $path = New-Object Drawing.Drawing2D.GraphicsPath
        $path.AddArc(0, 0, $h, $h, 90, 180); $path.AddArc(($w - $h), 0, $h, $h, 270, 180); $path.CloseFigure()
        $trackColor = if ($on) { $UiAccent } else { [Drawing.Color]::FromArgb(62, 76, 100) }
        $kb = New-Object Drawing.SolidBrush $trackColor
        $g.FillPath($kb, $path); $kb.Dispose()
        $knobColor = if ($on) { [Drawing.Color]::White } else { [Drawing.Color]::FromArgb(205, 213, 226) }
        $kb = New-Object Drawing.SolidBrush $knobColor
        $kx = if ($on) { $w - $h + 3 } else { 3 }
        $g.FillEllipse($kb, $kx, 3, ($h - 6), ($h - 6)); $kb.Dispose()
        if ($s.Focused) { $pen = New-Object Drawing.Pen $UiText, 1; $g.DrawPath($pen, $path); $pen.Dispose() }
        $path.Dispose()
    })
    $t.Add_Click({
        param($s, $e)
        $s.Tag.on = -not [bool]$s.Tag.on
        $s.Invalidate()
        if ($s.Tag.change) { & $s.Tag.change $s ([bool]$s.Tag.on) }
    })
    return $t
}

# Baslik + soluk tek satir aciklama solda, acma/kapama dugmesi sagda
function New-ToggleRow([string]$title, [string]$desc, [bool]$on, [int]$y, [scriptblock]$onChange) {
    $w = $SettingsCardW
    $card = New-Object Windows.Forms.Panel
    $card.Location = New-Object Drawing.Point(30, $y); $card.Size = New-Object Drawing.Size($w, 84); $card.BackColor = $UiSurface
    $card.Controls.Add((New-Label $title 18 14 $UiText (New-Font 10.5 'Bold')))
    $card.Controls.Add((New-Label $desc 18 40 $UiMuted (New-Font 9) ($w - 110)))
    $t = New-ToggleSwitch $on $onChange $title
    $t.Location = New-Object Drawing.Point(($w - 18 - 48), 29)
    $card.Controls.Add($t)
    $card.Region = New-RoundRegion $w 84 8
    return $card
}

function New-SettingsPage([string]$title, [string]$sub) {
    $p = New-Object Windows.Forms.Panel
    $p.Dock = 'Fill'; $p.BackColor = $UiBg; $p.AutoScroll = $true; $p.Visible = $false
    $p.Controls.Add((New-Label $title 30 24 $UiText (New-Font 18 'Bold')))
    $p.Controls.Add((New-Label $sub 30 62 $UiMuted (New-Font 9.5) $SettingsCardW))
    return $p
}

function New-SettingsCard([int]$y, [int]$h) {
    $card = New-Object Windows.Forms.Panel
    $card.Location = New-Object Drawing.Point(30, $y); $card.Size = New-Object Drawing.Size($SettingsCardW, $h); $card.BackColor = $UiSurface
    $card.Region = New-RoundRegion $SettingsCardW $h 8
    return $card
}

function New-SettingsHeading([string]$text, [int]$y) {
    return (New-Label $text.ToUpper([Globalization.CultureInfo]'tr-TR') 32 $y $UiAccent (New-Font 8.5 'Bold'))
}

function New-SettingsNote([string]$text, [int]$x, [int]$y, [int]$maxWidth = 570) {
    $l = New-Label $text $x $y $UiLevel.RED (New-Font 9) $maxWidth
    $l.Visible = $false
    return $l
}

function New-SettingsTextBox([string]$text, [int]$x, [int]$y, [int]$w) {
    $tb = New-Object Windows.Forms.TextBox
    $tb.Text = $text; $tb.Location = New-Object Drawing.Point($x, $y); $tb.Width = $w
    $tb.BackColor = $UiSurface2; $tb.ForeColor = $UiText; $tb.BorderStyle = 'FixedSingle'; $tb.Font = New-Font 10
    return $tb
}

function New-NavButton([string]$text, [int]$y) {
    $b = New-Object Windows.Forms.Button
    $b.Name = $text; $b.Text = $text; $b.Size = New-Object Drawing.Size(210, 44); $b.Location = New-Object Drawing.Point(0, $y)
    $b.FlatStyle = 'Flat'; $b.FlatAppearance.BorderSize = 0; $b.Cursor = 'Hand'
    $b.TextAlign = 'MiddleLeft'; $b.Padding = New-Object Windows.Forms.Padding(24, 0, 0, 0)
    $b.Font = New-Font 10.5; $b.BackColor = [Drawing.Color]::FromArgb(7, 16, 30); $b.ForeColor = $UiMuted
    $b.FlatAppearance.MouseOverBackColor = $UiSurface
    $b.Tag = 'off'
    $b.Add_Paint({
        param($s, $e)
        if ($s.Tag -eq 'sel') {
            $e.Graphics.SmoothingMode = 'AntiAlias'
            $br = New-Object Drawing.SolidBrush $UiAccent
            $e.Graphics.FillRectangle($br, 0, 9, 4, ($s.Height - 18)); $br.Dispose()
        }
    })
    return $b
}

# Her degisiklik aninda kaydedilir; altta kisa bir "Kaydedildi" belirir
function Show-SettingsSaved($ctx) {
    $ctx.flash.Text = 'Kaydedildi ✓'; $ctx.flash.Visible = $true
    $ctx.flashTimer.Stop(); $ctx.flashTimer.Start()
}

function Save-SettingsChange($ctx, [scriptblock]$apply) {
    try {
        $cfg = Get-Config
        & $apply $cfg
        Save-Config $cfg
        Show-SettingsSaved $ctx
    } catch {
        Write-Log "Ayar kaydedilemedi: $_"
        $ctx.flash.Text = 'Kaydedilemedi'; $ctx.flash.Visible = $true
    }
}

# ---- sayfalar

function Build-SettingsKoruma($ctx, $p, $cfg) {
    $r1 = New-ToggleRow 'Virüslü dosyaları otomatik karantinaya al' `
        'Kapalıyken Cortmed hiçbir dosyaya dokunmaz, sadece uyarır. Açıkken virüslü dosyalar açılamayacakları bir klasöre taşınır.' ($cfg.autoQuarantine -eq $true) 104 {
        param($s, $on)
        $c = $s.FindForm().Tag
        Save-SettingsChange $c { param($x) $x.autoQuarantine = $on }
    }
    $clamDesc = 'Arşivlerin ve kurulum dosyalarının içine de bakan üçüncü tarama motoru. İlk açılışta yaklaşık 500 MB indirir.'
    $clamState = Get-ClamStatusText
    if ($cfg.clamav -eq $true -and -not $clamState) { $clamDesc += '  Durum: hazır.' } elseif ($cfg.clamav -eq $true) { $clamDesc += "  Durum: $clamState." }
    $r2 = New-ToggleRow 'Ek tarama motoru (ClamAV)' $clamDesc ($cfg.clamav -eq $true) 204 {
        param($s, $on)
        $c = $s.FindForm().Tag
        Save-SettingsChange $c { param($x) $x.clamav = $on }
        # Acik ama hazir degilse (ilk acilis ya da yarida kalan kurulum) kurulumu baslat
        if ($on -and -not (Test-ClamReady) -and -not (Test-ClamInstalling)) {
            Start-ClamInstall
            [Windows.Forms.MessageBox]::Show($s.FindForm(), 'Ek tarama motoru arka planda kuruluyor. İnternet hızınıza göre 5-15 dakika sürer.', 'Cortmed Security') | Out-Null
        }
    }
    $r3 = New-ToggleRow 'Sessiz mod' `
        'Önemsiz bildirimleri gizler. Tehlikeli bir şey bulunursa kırmızı uyarı yine de gösterilir.' ($cfg.quietMode -eq $true) 304 {
        param($s, $on)
        $c = $s.FindForm().Tag
        Save-SettingsChange $c { param($x) $x.quietMode = $on }
    }
    $p.Controls.AddRange(@($r1, $r2, $r3))
}

function Build-SettingsGuard($ctx, $p) {
    $ctx.guardCard = $null
    $ctx.allowedHead = New-SettingsHeading 'İzin verdiğiniz programlar' 214
    $card = New-SettingsCard 238 150
    $lb = New-Object Windows.Forms.ListBox
    $lb.Location = New-Object Drawing.Point(14, 12); $lb.Size = New-Object Drawing.Size(($SettingsCardW - 28), 126)
    $lb.BorderStyle = 'None'; $lb.BackColor = $UiSurface; $lb.ForeColor = $UiText; $lb.SelectionMode = 'None'
    $lb.Font = New-Object Drawing.Font('Consolas', 10)
    $card.Controls.Add($lb)
    $ctx.allowedList = $lb
    $note = New-Label 'İzin verdiğiniz programlar. Bu listeyi değiştirmek için yönetici izni gerekir.' 32 402 $UiMuted (New-Font 9) $SettingsCardW
    $p.Controls.AddRange(@($ctx.allowedHead, $card, $note))
}

function Update-SettingsGuardPage($ctx) {
    $p = $ctx.pages['Davranış bekçisi']
    $gs = Get-GuardStatus
    $chk = Get-GuardCheck $gs
    if ($ctx.guardCard) { $p.Controls.Remove($ctx.guardCard); $ctx.guardCard.Dispose() }
    $dotColor = if ($chk.ok) { $UiLevel.OK } else { $UiLevel.YELLOW }
    $detail = if ($chk.ok) { 'Şüpheli davranan programlar çalışırken durdurulur ve size sorulur.' }
        elseif ($chk.hint) { [string]$chk.hint }
        elseif (-not $gs.installed) { 'Şüpheli davranan programları çalışırken durdurmak için bekçiyi açın.' }
        else { 'Bazı davranışlar görülmeyebilir.' }
    $btn = $null
    if ($chk.offer) {
        $btn = New-FlatButton $(if ($gs.installed) { 'Bekçiyi onar' } else { 'Bekçiyi aç' }) $true
        $btn.Add_Click({
            param($s, $e)
            $c = $s.FindForm().Tag
            if ($c.guardProc) { return }
            $gp = Start-GuardSetup
            if ($gp) { $c.guardProc = $gp; $s.Enabled = $false; $c.guardTimer.Start() }
        })
    }
    $card = New-Card $SettingsCardW 84 (New-LevelDot $dotColor) $chk.text $detail @($btn) 2 $ctx.tips
    $card.Location = New-Object Drawing.Point(30, 104)
    $p.Controls.Add($card); $ctx.guardCard = $card

    $al = Get-GuardAllowedList
    $ctx.allowedList.Items.Clear()
    if (-not $al.ok) { [void]$ctx.allowedList.Items.Add('Liste şu an okunamadı.'); $ctx.allowedHead.Text = 'İZİN VERDİĞİNİZ PROGRAMLAR' }
    elseif (-not $al.items.Count) { [void]$ctx.allowedList.Items.Add('Henüz izin verdiğiniz bir program yok.'); $ctx.allowedHead.Text = 'İZİN VERDİĞİNİZ PROGRAMLAR' }
    else {
        foreach ($h in $al.items) { [void]$ctx.allowedList.Items.Add(('Program  ' + $h.Substring(0, 16).ToLowerInvariant() + '…')) }
        $ctx.allowedHead.Text = 'İZİN VERDİĞİNİZ PROGRAMLAR ({0})' -f $al.items.Count
    }
}

function Build-SettingsDb($ctx, $p, $cfg) {
    $info = New-SettingsCard 104 132
    $y = 16
    foreach ($row in @(@('Sürüm', 'dbVer'), @('İmza sayısı', 'dbSigs'), @('Son güncelleme', 'dbLast'))) {
        $info.Controls.Add((New-Label $row[0] 18 $y $UiMuted (New-Font 9.5)))
        $v = New-Label '' 170 $y $UiText (New-Font 9.5) 420
        $info.Controls.Add($v); $ctx[$row[1]] = $v
        $y += 38
    }
    $upd = New-FlatButton 'Şimdi güncelle' $true
    $upd.AutoSize = $false; $upd.Size = New-Object Drawing.Size(170, 40); $upd.Location = New-Object Drawing.Point(30, 252)
    $upd.Add_Click({ param($s, $e) Start-DbUpdate ($s.FindForm().Tag) })
    $ctx.dbBtn = $upd
    $ctx.dbMsg = New-Label '' 216 262 $UiMuted (New-Font 9.5) 440

    # VirusTotal anahtari
    $vtCard = New-SettingsCard 322 176
    $vtCard.Controls.Add((New-Label 'İkinci görüş (isteğe bağlı)' 18 14 $UiText (New-Font 10.5 'Bold')))
    $vtCard.Controls.Add((New-Label 'Şüpheli dosyaları 70''ten fazla antivirüs programına sorar. Bunun için ücretsiz bir VirusTotal anahtarı gerekir.' 18 40 $UiMuted (New-Font 9) ($SettingsCardW - 36)))
    $vt = New-SettingsTextBox ([string]$cfg.vtKey) 18 84 ($SettingsCardW - 36 - 50)
    $vt.UseSystemPasswordChar = $true
    $vt.Add_TextChanged({
        param($s, $e)
        $c = $s.FindForm().Tag
        $v = $s.Text.Trim()
        if ($v -eq '' -or $v -match '^[0-9a-fA-F]{64}$') {
            $c.vtNote.Visible = $false
            Save-SettingsChange $c { param($x) $x.vtKey = $v }
        } else {
            $c.vtNote.Text = 'Anahtar 64 karakter olmalı (yalnızca 0-9 ve a-f). Doğru olana kadar kaydedilmez.'
            $c.vtNote.Visible = $true
        }
    })
    $eye = New-Object Windows.Forms.Button
    $eye.Text = '👁'; $eye.Font = New-Object Drawing.Font('Segoe UI Emoji', 10); $eye.FlatStyle = 'Flat'; $eye.Cursor = 'Hand'
    $eye.Size = New-Object Drawing.Size(40, 28); $eye.Location = New-Object Drawing.Point(($SettingsCardW - 18 - 40), 83)
    $eye.BackColor = $UiSurface2; $eye.ForeColor = $UiMuted; $eye.FlatAppearance.BorderColor = [Drawing.Color]::FromArgb(48, 72, 108)
    $ctx.tips.SetToolTip($eye, 'Anahtarı göster / gizle')
    $eye.AccessibleName = 'Anahtarı göster veya gizle'
    $eye.Add_Click({
        param($s, $e)
        $c = $s.FindForm().Tag
        $c.vtBox.UseSystemPasswordChar = -not $c.vtBox.UseSystemPasswordChar
        $s.ForeColor = if ($c.vtBox.UseSystemPasswordChar) { $UiMuted } else { $UiAccent }
    })
    $link = New-Object Windows.Forms.LinkLabel
    $link.Text = 'Ücretsiz anahtar al (virustotal.com)'; $link.AutoSize = $true; $link.Location = New-Object Drawing.Point(18, 122)
    $link.LinkColor = $UiAccent; $link.ActiveLinkColor = $UiText; $link.Font = New-Font 9
    $link.Add_LinkClicked({ Start-Process 'https://www.virustotal.com/gui/join-us' })
    $ctx.vtBox = $vt
    $ctx.vtNote = New-SettingsNote '' 18 146
    $vtCard.Controls.AddRange(@($vt, $eye, $link, $ctx.vtNote))
    $p.Controls.AddRange(@($info, $upd, $ctx.dbMsg, $vtCard))
}

function Update-SettingsDbPage($ctx) {
    $verFile = Join-Path $DataDir 'db-version.txt'
    $ver = ''
    try { if (Test-Path -LiteralPath $verFile) { $ver = (Get-Content -LiteralPath $verFile -Raw -Encoding UTF8).Trim() } } catch { }
    $status = Read-Json $StatusPath $null
    $build = $null; $sigs = $null
    if ($script:Db) { $build = $script:Db.BuildTime; $sigs = $script:Db.SignatureCount }
    elseif ($status) { $build = $status.dbTime; $sigs = $status.signatures }
    $date = ''
    if ($build) { try { $date = '{0:dd.MM.yyyy}' -f ([DateTimeOffset]::FromUnixTimeSeconds([long]$build).LocalDateTime) } catch { } }
    $parts = @($ver, $date) | Where-Object { $_ }
    $ctx.dbVer.Text = if ($parts) { $parts -join '  ·  ' } else { 'Paketle gelen sürüm' }
    $ctx.dbSigs.Text = if ($sigs) { '{0:N0}' -f [int]$sigs } else { 'Bilinmiyor' }
    $last = 'Henüz güncelleme yapılmadı'
    $rf = Join-Path $DataDir 'db-update.txt'
    try {
        if (Test-Path -LiteralPath $rf) {
            $raw = (Get-Content -LiteralPath $rf -Raw -Encoding UTF8).Trim()
            $i = $raw.IndexOf('|')
            if ($i -gt 0) { $last = '{0:dd.MM.yyyy HH:mm}  ·  {1}' -f [datetime]$raw.Substring(0, $i), $raw.Substring($i + 1) }
        }
    } catch { }
    $ctx.dbLast.Text = $last
}

# Guncelleme ayri bir surecte calisir (pencere donmaz); sonuc zamanlayicida okunur
function Start-DbUpdate($ctx) {
    if ($ctx.updProc) { return }
    $out = Join-Path ([IO.Path]::GetTempPath()) ('cortmed-upd-' + [Guid]::NewGuid().ToString('N') + '.txt')
    $script = (Join-Path $Root 'CortmedSecurity.ps1').Replace("'", "''")
    $cmd = "[Console]::OutputEncoding = [Text.Encoding]::UTF8; & '$script' -Mode Update"
    $ctx.dbBtn.Enabled = $false; $ctx.dbBtn.Text = 'Güncelleniyor…'
    $ctx.dbMsg.ForeColor = $UiMuted; $ctx.dbMsg.Text = 'Güncelleme denetleniyor. Bu birkaç dakika sürebilir.'
    try {
        $ctx.updOut = $out
        $ctx.updProc = Start-Process powershell.exe -WindowStyle Hidden -PassThru -RedirectStandardOutput $out -ArgumentList @(
            '-NoProfile', '-ExecutionPolicy', 'Bypass', '-Command', ('"{0}"' -f $cmd))
        $null = $ctx.updProc.Handle
        $ctx.updTimer.Start()
    } catch {
        $ctx.updProc = $null
        Complete-DbUpdate $ctx ''
    }
}

function Complete-DbUpdate($ctx, [string]$msg) {
    $ctx.dbBtn.Enabled = $true; $ctx.dbBtn.Text = 'Şimdi güncelle'
    $ok = [bool]$msg
    if (-not $ok) { $msg = 'Güncellenemedi. İnternet bağlantısını ve güncelleme adresini kontrol edin.' }
    $ctx.dbMsg.ForeColor = if ($ok) { $UiLevel.OK } else { $UiLevel.RED }
    $ctx.dbMsg.Text = $msg
    try { Set-Content -LiteralPath (Join-Path $DataDir 'db-update.txt') -Value ('{0}|{1}' -f (Get-Date).ToString('o'), $msg) -Encoding UTF8 } catch { }
    if ($ok) { try { Initialize-Engine } catch { } }
    Update-SettingsDbPage $ctx
}

function Update-SettingsTrustedPage($ctx) {
    $flow = $ctx.trustFlow
    $flow.SuspendLayout()
    foreach ($c in @($flow.Controls)) { $flow.Controls.Remove($c); $c.Dispose() }
    $hashes = @((Get-Config).trustedHashes | Where-Object { $_ } | ForEach-Object { [string]$_ })
    $ctx.trustCount.Text = if ($hashes.Count) { "$($hashes.Count) dosya güvenilir olarak işaretli." } else { 'Güvenilir olarak işaretli dosya yok.' }
    $ctx.trustReset.Enabled = [bool]$hashes.Count
    if (-not $hashes.Count) {
        $flow.Controls.Add((New-Label 'Henüz güvendiğiniz bir dosya yok.' 0 0 $UiMuted (New-Font 10)))
    }
    foreach ($h in $hashes) {
        $short = if ($h.Length -gt 16) { $h.Substring(0, 16) + '…' } else { $h }
        $rm = New-FlatButton 'Kaldır' $false 'muted'
        $rm.Tag = $h
        $rm.Add_Click({
            param($s, $e)
            $c = $s.FindForm().Tag; $h = [string]$s.Tag
            Save-SettingsChange $c { param($x) $x.trustedHashes = @(@($x.trustedHashes) | Where-Object { $_ -and $_ -ne $h }) }
            Update-SettingsTrustedPage $c
        })
        $card = New-Card 590 62 $null $short "Dosya adı kaydedilmemiş. Tam parmak izi: $h" @($rm) 1 $ctx.tips
        $flow.Controls.Add($card)
    }
    $flow.ResumeLayout()
}

function Build-SettingsTrusted($ctx, $p) {
    $ctx.trustCount = New-Label '' 32 108 $UiText (New-Font 10.5 'Bold')
    $reset = New-FlatButton 'Hepsini sıfırla' $false 'muted'
    $reset.AutoSize = $false; $reset.Size = New-Object Drawing.Size(160, 38); $reset.Location = New-Object Drawing.Point(($SettingsCardW + 30 - 160), 98)
    $reset.Add_Click({
        param($s, $e)
        $c = $s.FindForm().Tag
        $n = @((Get-Config).trustedHashes | Where-Object { $_ }).Count
        $a = [Windows.Forms.MessageBox]::Show($s.FindForm(),
            "Güvendiğiniz $n dosyanın hepsi listeden çıkarılacak. Bu dosyalar için Cortmed yeniden uyarı verebilir. Devam edilsin mi?",
            'Hepsini sıfırla', 'YesNo', 'Warning')
        if ($a -ne 'Yes') { return }
        Save-SettingsChange $c { param($x) $x.trustedHashes = @() }
        Update-SettingsTrustedPage $c
    })
    $flow = New-Object Windows.Forms.FlowLayoutPanel
    $flow.Location = New-Object Drawing.Point(30, 148); $flow.Size = New-Object Drawing.Size(($SettingsCardW + 20), 412)
    $flow.FlowDirection = 'TopDown'; $flow.WrapContents = $false; $flow.AutoScroll = $true; $flow.BackColor = $UiBg
    $ctx.trustFlow = $flow; $ctx.trustReset = $reset
    $p.Controls.AddRange(@($ctx.trustCount, $reset, $flow))
}

function Update-SettingsQuarantinePage($ctx) {
    $flow = $ctx.quarFlow
    $flow.SuspendLayout()
    foreach ($c in @($flow.Controls)) { $flow.Controls.Remove($c); $c.Dispose() }
    $files = @(Get-ChildItem -LiteralPath $QuarantineDir -File -ErrorAction SilentlyContinue | Sort-Object LastWriteTime -Descending | Select-Object -First 200)
    $ctx.quarCount.Text = if ($files.Count) { "$($files.Count) dosya karantinada." } else { 'Karantinada dosya yok.' }
    if (-not $files.Count) {
        $flow.Controls.Add((New-Label 'Karantinaya alınmış bir dosya yok. Cortmed dosyaları kendiliğinden silmez.' 0 0 $UiMuted (New-Font 10)))
    }
    foreach ($fi in $files) {
        $name = $fi.Name; $when = $fi.LastWriteTime
        if ($fi.Name -match '^(\d{8}-\d{6})_(.+)\.karantina$') {
            $name = $Matches[2]
            try { $when = [datetime]::ParseExact($Matches[1], 'yyyyMMdd-HHmmss', [Globalization.CultureInfo]::InvariantCulture) } catch { }
        }
        $card = New-Card 590 62 $null $name ('{0:dd.MM.yyyy HH:mm}  ·  {1}' -f $when, (Format-Size $fi.Length)) @() 1 $ctx.tips
        $flow.Controls.Add($card)
    }
    $flow.ResumeLayout()
}

function Build-SettingsQuarantine($ctx, $p) {
    $ctx.quarCount = New-Label '' 32 108 $UiText (New-Font 10.5 'Bold')
    $open = New-FlatButton 'Klasörü aç' $false 'muted'
    $open.AutoSize = $false; $open.Size = New-Object Drawing.Size(160, 38); $open.Location = New-Object Drawing.Point(($SettingsCardW + 30 - 160), 98)
    $open.Add_Click({ Start-Process explorer.exe $QuarantineDir })
    $flow = New-Object Windows.Forms.FlowLayoutPanel
    $flow.Location = New-Object Drawing.Point(30, 148); $flow.Size = New-Object Drawing.Size(($SettingsCardW + 20), 412)
    $flow.FlowDirection = 'TopDown'; $flow.WrapContents = $false; $flow.AutoScroll = $true; $flow.BackColor = $UiBg
    $ctx.quarFlow = $flow
    $p.Controls.AddRange(@($ctx.quarCount, $open, $flow))
}

function Build-SettingsAdvanced($ctx, $p, $cfg) {
    $card = New-SettingsCard 104 150
    $card.Controls.Add((New-Label 'Güncelleme adresi' 18 14 $UiText (New-Font 10.5 'Bold')))
    $card.Controls.Add((New-Label 'Bunu değiştirmeniz gerekmez' 18 40 $UiMuted (New-Font 9)))
    $tb = New-SettingsTextBox ([string]$cfg.updateUrl) 18 70 ($SettingsCardW - 36)
    $tb.Font = New-Font 9.5
    $tb.Add_TextChanged({
        param($s, $e)
        $c = $s.FindForm().Tag
        $v = $s.Text.Trim()
        if ($v -eq '' -or $v -match '^https?://\S+$') {
            $c.urlNote.Visible = $false
            Save-SettingsChange $c { param($x) $x.updateUrl = $v }
        } else {
            $c.urlNote.Text = 'Adres http:// ya da https:// ile başlamalı. Doğru olana kadar kaydedilmez.'
            $c.urlNote.Visible = $true
        }
    })
    $ctx.urlBox = $tb
    $ctx.urlNote = New-SettingsNote '' 18 100
    $reset = New-Object Windows.Forms.LinkLabel
    $reset.Text = 'Varsayılan adrese dön'; $reset.AutoSize = $true; $reset.Location = New-Object Drawing.Point(18, 120)
    $reset.LinkColor = $UiAccent; $reset.ActiveLinkColor = $UiText; $reset.Font = New-Font 9
    $reset.Add_LinkClicked({ param($s, $e) $s.FindForm().Tag.urlBox.Text = $DefaultUpdateUrl })
    $card.Controls.AddRange(@($tb, $ctx.urlNote, $reset))

    $logBtn = New-FlatButton 'Kayıt dosyasını aç'
    $logBtn.Add_Click({
        param($s, $e)
        if (Test-Path -LiteralPath $LogPath) { Start-Process notepad.exe ('"{0}"' -f $LogPath) }
        else { [Windows.Forms.MessageBox]::Show($s.FindForm(), 'Henüz bir kayıt dosyası oluşmadı.', 'Cortmed Security') | Out-Null }
    })
    $logCard = New-Card $SettingsCardW 84 $null 'Kayıt dosyası' 'Cortmed''in neler yaptığını gösteren düz yazı dosyası.' @($logBtn) 1 $ctx.tips
    $logCard.Location = New-Object Drawing.Point(30, 274)
    $p.Controls.AddRange(@($card, $logCard))
}

function Build-SettingsAbout($ctx, $p) {
    $logo = Get-CortmedLogo
    if ($logo) {
        $pic = New-Object Windows.Forms.PictureBox
        $pic.Image = $logo; $pic.SizeMode = 'Zoom'; $pic.Size = New-Object Drawing.Size(96, 96); $pic.Location = New-Object Drawing.Point(30, 110)
        $p.Controls.Add($pic)
    }
    $p.Controls.Add((New-Label 'Cortmed Security' 144 120 $UiText (New-Font 20 'Bold')))
    $ver = ''
    $vf = Join-Path $Root 'version.txt'
    try {
        if (Test-Path -LiteralPath $vf) { $ver = 'Sürüm ' + (Get-Content -LiteralPath $vf -Raw -Encoding UTF8).Trim() }
        else { $ver = 'Sürüm tarihi: {0:dd.MM.yyyy}' -f (Get-Item -LiteralPath (Join-Path $Root 'CortmedSecurity.ps1')).LastWriteTime }
    } catch { }
    $p.Controls.Add((New-Label $ver 146 160 $UiMuted (New-Font 10)))
    $p.Controls.Add((New-Label 'Ailenizin bilgisayarını arka planda koruyan, ücretsiz ve sade bir güvenlik aracı.' 146 190 $UiText (New-Font 10) 460))
    $link = New-Object Windows.Forms.LinkLabel
    $link.Text = $AboutUrl; $link.AutoSize = $true; $link.Location = New-Object Drawing.Point(146, 242)
    $link.LinkColor = $UiAccent; $link.ActiveLinkColor = $UiText; $link.Font = New-Font 10
    $link.Add_LinkClicked({ Start-Process 'https://github.com/cortmed/CortmedSecurity' })
    $p.Controls.Add($link)
}

function Select-SettingsPage($ctx, [string]$name) {
    foreach ($k in $ctx.pages.Keys) { $ctx.pages[$k].Visible = ($k -eq $name) }
    foreach ($k in $ctx.nav.Keys) {
        $b = $ctx.nav[$k]; $on = ($k -eq $name)
        $b.Tag = if ($on) { 'sel' } else { 'off' }
        $b.BackColor = if ($on) { $UiSurface2 } else { [Drawing.Color]::FromArgb(7, 16, 30) }
        $b.ForeColor = if ($on) { $UiText } else { $UiMuted }
        $b.Invalidate()
    }
    switch ($name) {
        'Davranış bekçisi' { Update-SettingsGuardPage $ctx }
        'Veritabanı' { Update-SettingsDbPage $ctx }
        'Güvenilir dosyalar' { Update-SettingsTrustedPage $ctx }
        'Karantina' { Update-SettingsQuarantinePage $ctx }
    }
}

# Ayarlar penceresini kurar (gostermez). Tum durum $form.Tag icindeki $ctx'te; olay islemcileri ona FindForm().Tag ile ulasir.
function New-SettingsForm {
    $cfg = Get-Config
    $f = New-DarkForm 'Cortmed Security - Ayarlar' 900 640
    $f.FormBorderStyle = 'FixedDialog'; $f.MaximizeBox = $false; $f.MinimizeBox = $false
    $f.ClientSize = New-Object Drawing.Size(900, 620)
    $ctx = @{ form = $f; pages = [ordered]@{}; nav = [ordered]@{}; tips = (New-Object Windows.Forms.ToolTip); guardProc = $null; updProc = $null; updOut = $null }
    $f.Tag = $ctx

    # Sag taraf: sayfalar + alt serit (Kaydedildi / Kapat)
    $right = New-Object Windows.Forms.Panel
    $right.Dock = 'Fill'; $right.BackColor = $UiBg
    $host1 = New-Object Windows.Forms.Panel
    $host1.Dock = 'Fill'; $host1.BackColor = $UiBg
    $bar = New-Object Windows.Forms.Panel
    $bar.Dock = 'Bottom'; $bar.Height = 60; $bar.BackColor = [Drawing.Color]::FromArgb(7, 16, 30)
    $ctx.flash = New-Label '' 30 19 $UiLevel.OK (New-Font 10.5 'Bold')
    $ctx.flash.Visible = $false
    $close = New-FlatButton 'Kapat' $true
    $close.AutoSize = $false; $close.Size = New-Object Drawing.Size(120, 38); $close.Location = New-Object Drawing.Point((690 - 30 - 120), 11)
    $close.Add_Click({ param($s, $e) $s.FindForm().Close() })
    $bar.Controls.AddRange(@($ctx.flash, $close))
    $f.CancelButton = $close
    $right.Controls.AddRange(@($host1, $bar))

    # Sol gezinme listesi
    $nav = New-Object Windows.Forms.Panel
    $nav.Dock = 'Left'; $nav.Width = 210; $nav.BackColor = [Drawing.Color]::FromArgb(7, 16, 30)
    $nav.Controls.Add((New-Label 'Ayarlar' 24 22 $UiText (New-Font 17 'Bold')))
    $y = 78
    foreach ($n in $SettingsPageNames) {
        $b = New-NavButton $n $y; $y += 46
        $b.Add_Click({ param($s, $e) Select-SettingsPage ($s.FindForm().Tag) $s.Name })
        $nav.Controls.Add($b); $ctx.nav[$n] = $b
    }
    $f.Controls.AddRange(@($right, $nav))

    # Zamanlayicilar
    $ctx.flashTimer = New-Object Windows.Forms.Timer
    $ctx.flashTimer.Interval = 2200; $ctx.flashTimer.Tag = $ctx
    $ctx.flashTimer.Add_Tick({ param($s, $e) $s.Stop(); $s.Tag.flash.Visible = $false })
    $ctx.updTimer = New-Object Windows.Forms.Timer
    $ctx.updTimer.Interval = 1000; $ctx.updTimer.Tag = $ctx
    $ctx.updTimer.Add_Tick({
        param($s, $e)
        $c = $s.Tag
        if (-not $c.updProc -or -not $c.updProc.HasExited) { return }
        $s.Stop()
        $msg = ''
        try {
            if (Test-Path -LiteralPath $c.updOut) {
                $lines = @((Get-Content -LiteralPath $c.updOut -Raw -Encoding UTF8) -split "`r?`n" | ForEach-Object { $_.Trim([char]0xFEFF).Trim() } | Where-Object { $_ })
                if ($lines) { $msg = $lines[-1] }
                Remove-Item -LiteralPath $c.updOut -Force -ErrorAction SilentlyContinue
            }
        } catch { }
        $c.updProc = $null
        Complete-DbUpdate $c $msg
    })
    $ctx.guardTimer = New-Object Windows.Forms.Timer
    $ctx.guardTimer.Interval = 1500; $ctx.guardTimer.Tag = $ctx
    $ctx.guardTimer.Add_Tick({
        param($s, $e)
        $c = $s.Tag
        if (-not $c.guardProc -or -not $c.guardProc.HasExited) { return }
        $s.Stop()
        $code = $null
        try { $code = $c.guardProc.ExitCode } catch { }
        $c.guardProc = $null
        Update-SettingsGuardPage $c
        $note = Get-GuardSetupNote $code
        if ($note) { [Windows.Forms.MessageBox]::Show($c.form, $note, 'Cortmed Security') | Out-Null }
    })
    $f.Add_FormClosed({
        param($s, $e)
        foreach ($t in @($s.Tag.flashTimer, $s.Tag.updTimer, $s.Tag.guardTimer)) { if ($t) { $t.Stop(); $t.Dispose() } }
    })

    # Sayfalar
    $subs = @{
        'Koruma' = 'Cortmed''in sizi nasıl koruyacağını seçin. Değişiklikler hemen kaydedilir.'
        'Davranış bekçisi' = 'Şüpheli davranan programları çalışırken durdurur ve size sorar.'
        'Veritabanı' = 'Bilinen virüslerin listesi her gün kendiliğinden güncellenir.'
        'Güvenilir dosyalar' = 'Güvendiğinizi söylediğiniz dosyalar için Cortmed uyarı vermez.'
        'Karantina' = 'Karantinaya alınan dosyalar açılamayacakları bir klasörde bekler.'
        'Gelişmiş' = 'Çoğu kişinin buraya bakması gerekmez.'
        'Hakkında' = ''
    }
    foreach ($n in $SettingsPageNames) {
        $pg = New-SettingsPage $n $subs[$n]
        $ctx.pages[$n] = $pg; $host1.Controls.Add($pg)
    }
    Build-SettingsKoruma $ctx $ctx.pages['Koruma'] $cfg
    Build-SettingsGuard $ctx $ctx.pages['Davranış bekçisi']
    Build-SettingsDb $ctx $ctx.pages['Veritabanı'] $cfg
    Build-SettingsTrusted $ctx $ctx.pages['Güvenilir dosyalar']
    Build-SettingsQuarantine $ctx $ctx.pages['Karantina']
    Build-SettingsAdvanced $ctx $ctx.pages['Gelişmiş'] $cfg
    Build-SettingsAbout $ctx $ctx.pages['Hakkında']
    Select-SettingsPage $ctx 'Koruma'
    return $f
}

function Show-Settings($owner) {
    $f = New-SettingsForm
    [void]$f.ShowDialog($owner)
}

# ------------------------------------------------------------------ panel

# Oneriler tek tek degil, konu basliklari altinda ve "bizim onerimiz" olarak sunulur
$AdviceCategories = @(
    @{ id = 'protect'; prefixes = @('defender-extra', 'firewall', 'dns', 'smartscreen', 'uac', 'defender-old')
        icon = '🛡'; title = 'Windows korumalarını güçlendirin'
        text = 'Windows''un ücretsiz ama kapalı gelen korumalarını tek tıkla açın: zararlı site engelleme, istenmeyen program engelleme ve güvenlik duvarı.'
        button = 'Tek tıkla aç' }
    @{ id = 'updates'; prefixes = @('updates')
        icon = '⟳'; title = 'Windows''u güncel tutun'
        text = 'Güncellemeler, virüslerin kullandığı güvenlik açıklarını kapatır.'
        button = 'Windows Update''i aç' }
    @{ id = 'account'; prefixes = @('admin')
        icon = '👤'; title = 'Günlük işler için ayrı bir hesap kullanın'
        text = 'Yönetici olmayan bir hesap, virüslerin bilgisayara yerleşmesini çok zorlaştırır. İsterseniz sonra yaparsınız.'
        button = 'Nasıl yapılır?' }
    @{ id = 'programs'; prefixes = @('file', 'unsigned', 'persist-unsigned', 'persist-script', 'startup-script')
        icon = '📄'; title = 'Tanınmayan programlar'
        text = '{0} programın üreticisi doğrulanamıyor. Tanıdığınız programlarsa bir şey yapmanıza gerek yok.'
        button = 'Listeyi göster' }
    # Davranis bekcisi bulgulari ozgun seviyeye (guardLevel) gore: sari = supheli ama durdurulmadi (50-79 ya da
    # dondurulamadi), kirmizi = kullanici "Programi kapat" dedi
    @{ id = 'guard-warn'; prefixes = @('behavior'); guardLevel = 'YELLOW'
        icon = '⚠'; title = 'Şüpheli davranan programlar'
        text = 'Bu programlar şüpheli bir şey yaptı ama durdurulmadı. Tanımıyorsanız listeden açıp ''Karantinaya al'' ile kaldırın.'
        button = 'Listeyi göster' }
    @{ id = 'guard-history'; prefixes = @('behavior'); guardLevel = 'RED'
        icon = '🛑'; title = 'Durdurulan programlar'
        text = 'Cortmed bu programları durdurdu ve sizin onayınızla kapattı. Dosyaları hâlâ bilgisayarınızda; tanımıyorsanız listeden açıp ''Karantinaya al'' ile kaldırın.'
        button = 'Listeyi göster' }
)

# Davranis bekcisi hizmeti kurulu degilse en uste gelen oneri
$GuardAdvice = @{ id = 'guard'; icon = '🔒'; title = 'Davranış bekçisini açın'
    text = 'Şüpheli davranan programları (örneğin dosyalarınızı şifrelemeye çalışanları) çalışırken durdurur ve size sorar. Windows bir kez izin ister.'
    button = 'Bekçiyi aç' }

function Get-AdviceGroups($advice, [bool]$guardMissing = $false, [string]$guardHint = '') {
    $groups = @()
    if ($guardMissing) {
        $cat = $GuardAdvice.Clone()
        if ($guardHint) { $cat.text = $guardHint }
        $groups += [pscustomobject]@{ cat = $cat; items = @() }
    }
    $used = @{}
    foreach ($c in $AdviceCategories) {
        $items = @($advice | Where-Object { ($_.key -split ':')[0] -in $c.prefixes -and
                (-not $c.guardLevel -or ($_.PSObject.Properties['guardLevel'] -and $_.guardLevel -eq $c.guardLevel)) })
        foreach ($i in $items) { $used[$i.key] = $true }
        if ($items) { $groups += [pscustomobject]@{ cat = $c; items = $items } }
    }
    $rest = @($advice | Where-Object { -not $used.ContainsKey($_.key) })
    if ($rest) {
        $groups += [pscustomobject]@{ cat = @{ id = 'other'; icon = '•'; title = 'Diğer öneriler'; text = '{0} öneri daha var.'; button = 'Listeyi göster' }; items = $rest }
    }
    return $groups
}

function Show-Panel {
    # Tek pencere: zaten aciksa one getir
    $panelMutex = New-Object Threading.Mutex($false, 'Local\CortmedSecurityPanel')
    if (-not $panelMutex.WaitOne(0)) { $null = (New-Object -ComObject WScript.Shell).AppActivate('Cortmed Security'); return }
    # Gorev cubugunda PowerShell degil Cortmed simgesi gorunsun
    try { Initialize-EngineType; [Cortmed.AppIdentity]::ApplyToProcess() } catch { }
    # Gercek zamanli koruma calismiyorsa baslat
    if (-not (Test-WatcherRunning)) { [void](Start-Background 'Watch') }
    [Windows.Forms.Application]::EnableVisualStyles()

    $form = New-Object Windows.Forms.Form
    $form.Text = 'Cortmed Security'
    $form.Size = New-Object Drawing.Size(940, 780)
    $form.MinimumSize = New-Object Drawing.Size(800, 660)
    $form.StartPosition = 'CenterScreen'
    $form.Font = New-Font 10
    $form.BackColor = $UiBg; $form.ForeColor = $UiText
    $icon = Get-CortmedIcon; if ($icon) { $form.Icon = $icon }
    Set-WindowChrome $form
    $tips = New-Object Windows.Forms.ToolTip

    $state = @{ level = 'NONE'; symbol = 'dots'; title = ''; line = ''; tab = ''; checks = @(); scan = $null; harden = $null; guardSetup = $null }
    $fTitle = New-Font 21 'Bold'; $fLine = New-Font 10.5; $fCheck = New-Font 9

    # Durum alani: buyuk kalkan (duruma gore yesil / sari / kirmizi), baslik, tek satir bilgi ve ikincil kontroller
    $status = New-Object Windows.Forms.Panel
    $status.Dock = 'Top'; $status.Height = 262; $status.BackColor = $UiBg
    $status.GetType().GetProperty('DoubleBuffered', [Reflection.BindingFlags]'NonPublic,Instance').SetValue($status, $true, $null)
    $status.Add_Paint({
        param($sender, $e)
        $g = $e.Graphics
        $g.SmoothingMode = 'AntiAlias'; $g.TextRenderingHint = 'ClearTypeGridFit'
        $c = $UiLevel[$state.level]
        $cx = [int]($sender.Width / 2)
        # Kalkanin arkasinda yumusak isik
        foreach ($i in 0..6) {
            $r = 96 - $i * 11
            $br = New-Object Drawing.SolidBrush ([Drawing.Color]::FromArgb(9 + $i * 2, $c))
            $g.FillEllipse($br, ($cx - $r), (70 - $r), ($r * 2), ($r * 2)); $br.Dispose()
        }
        Draw-Shield $g ($cx - 45) 14 112 $c $state.symbol
        $fmt = New-Object Drawing.StringFormat; $fmt.Alignment = 'Center'
        $tb = New-Object Drawing.SolidBrush $UiText
        $g.DrawString($state.title, $fTitle, $tb, (New-Object Drawing.RectangleF(0, 134, $sender.Width, 38)), $fmt)
        $mb = New-Object Drawing.SolidBrush $UiMuted
        $g.DrawString($state.line, $fLine, $mb, (New-Object Drawing.RectangleF(24, 175, ($sender.Width - 48), 24)), $fmt)
        # Koruma kontrolleri: kucuk ve soluk, ama neyin calistigi gorunsun
        $rows = @(); $cur = @(); $curW = 0; $maxW = $sender.Width - 60
        foreach ($chk in $state.checks) {
            $tw = [int]$g.MeasureString($chk.text, $fCheck).Width + 22
            if ($cur.Count -and ($curW + $tw) -gt $maxW) { $rows += , @($cur); $cur = @(); $curW = 0 }
            $cur += , @($chk, $tw); $curW += $tw + 14
        }
        if ($cur.Count) { $rows += , @($cur) }
        $y = 212
        foreach ($row in $rows) {
            $total = 0; foreach ($it in $row) { $total += $it[1] + 14 }
            $x = [int](($sender.Width - $total + 14) / 2)
            foreach ($it in $row) {
                $col = if ($it[0].ok) { $UiLevel.OK } else { $UiLevel.YELLOW }
                $db = New-Object Drawing.SolidBrush $col
                $g.FillEllipse($db, $x, ($y + 5), 8, 8); $db.Dispose()
                $g.DrawString($it[0].text, $fCheck, $mb, ($x + 14), $y)
                $x += $it[1] + 14
            }
            $y += 22
        }
        $tb.Dispose(); $mb.Dispose()
    })
    $status.Add_Resize({ $status.Invalidate() })

    # Sekmeler
    $tabsBar = New-Object Windows.Forms.Panel
    $tabsBar.Dock = 'Top'; $tabsBar.Height = 52; $tabsBar.BackColor = $UiBg
    $tabThreat = New-Object Windows.Forms.Button
    $tabAdvice = New-Object Windows.Forms.Button
    $x = 16
    foreach ($tb in @($tabThreat, $tabAdvice)) {
        $tb.FlatStyle = 'Flat'; $tb.Cursor = 'Hand'; $tb.Height = 36; $tb.Width = 170
        $tb.Location = New-Object Drawing.Point($x, 10); $x += 180
        $tb.Font = New-Font 10.5 'Bold'
        $tabsBar.Controls.Add($tb)
    }

    # Icerik: tehdit kartlari / bos durum / oneri kartlari
    $content = New-Object Windows.Forms.Panel
    $content.Dock = 'Fill'; $content.Padding = New-Object Windows.Forms.Padding(16, 0, 16, 0); $content.BackColor = $UiBg
    $threatFlow = New-CardFlow
    $empty = New-Object Windows.Forms.Label
    $empty.Dock = 'Fill'; $empty.TextAlign = 'MiddleCenter'; $empty.BackColor = $UiSurface
    $empty.Font = New-Font 13 'Bold'; $empty.ForeColor = $UiLevel.OK
    $adviceFlow = New-CardFlow
    $content.Controls.AddRange(@($threatFlow, $empty, $adviceFlow))
    $onDone = { param($card) & $render }
    # Alt cubuk: iki ana is + ayarlar
    $bottom = New-Object Windows.Forms.Panel
    $bottom.Dock = 'Bottom'; $bottom.Height = 70; $bottom.BackColor = $UiBg
    $left = New-Object Windows.Forms.FlowLayoutPanel
    $left.Dock = 'Fill'; $left.Padding = New-Object Windows.Forms.Padding(16, 14, 0, 10); $left.BackColor = $UiBg
    $btnScan = New-FlatButton 'Tam Tarama Yap' $true
    $btnFile = New-FlatButton 'Bir Dosyayı Kontrol Et'
    $tips.SetToolTip($btnScan, 'Bilgisayarı baştan sona tarar: indirilen dosyalar, açılışta çalışan programlar ve güvenlik ayarları.')
    $tips.SetToolTip($btnFile, 'Seçtiğiniz bir dosyanın güvenli olup olmadığını söyler.')
    $left.Controls.AddRange(@($btnScan, $btnFile))
    $right = New-Object Windows.Forms.FlowLayoutPanel
    $right.Dock = 'Right'; $right.Width = 150; $right.Padding = New-Object Windows.Forms.Padding(0, 14, 16, 10); $right.BackColor = $UiBg
    $right.FlowDirection = 'RightToLeft'
    $btnSettings = New-FlatButton '⚙  Ayarlar'
    $tips.SetToolTip($btnSettings, 'Koruma seçenekleri, ek tarama motoru, virüs veritabanı ve karantina.')
    $right.Controls.Add($btnSettings)
    $bottom.Controls.AddRange(@($left, $right))


    $render = {
        $sum = Get-StatusSummary
        $s = $sum.status
        $threats = $sum.threats; $advice = $sum.advice
        if (-not $state.tab) { $state.tab = if ($threats) { 'threat' } else { 'advice' } }
        $guardState = Get-GuardStatus
        $guardCheck = Get-GuardCheck $guardState
        $groups = @(Get-AdviceGroups $advice ([bool]$guardCheck.offer) ([string]$guardCheck.hint))

        # Durum alani: kalkanin rengi ve basligi mevcut ozetten gelir (tehlike / bakilacak sey / korunuyor)
        $running = Test-WatcherRunning
        $sigs = if ($s -and $s.signatures) { '{0:N0} imza' -f [int]$s.signatures } else { 'hazır' }
        if ($state.scan) {
            $state.level = 'NONE'; $state.symbol = 'dots'; $state.title = 'Taranıyor…'
            $state.line = 'Bilgisayarınız taranıyor; bu sırada kullanmaya devam edebilirsiniz.'
        } elseif (-not $s) {
            $state.level = 'NONE'; $state.symbol = 'dots'; $state.title = 'İlk tarama bekleniyor'
            $state.line = 'Cortmed ilk taramayı birkaç dakika içinde kendiliğinden yapacak.'
        } else {
            if ($sum.reds) { $state.level = 'RED'; $state.symbol = 'cross'; $state.title = 'Tehlike bulundu' }
            # Oneriler kalkani sarartmaz; yalnizca tehditler sarartir (kullanici guvende hissetmeli)
            elseif ($threats) { $state.level = 'YELLOW'; $state.symbol = 'alert'; $state.title = 'Bakmanız gereken bir şey var' }
            else { $state.level = 'OK'; $state.symbol = 'check'; $state.title = 'Bilgisayarınız korunuyor' }
            $state.line = 'Son tarama: {0}  ·  Veritabanı: {1}' -f (Get-RelativeTime $sum.time), $sigs
        }
        $engines = 'Defender + YARA' + $(if (Test-ClamReady) { ' + ClamAV' } else { '' })
        $state.checks = @(
            @{ ok = $running; text = $(if ($running) { 'Gerçek zamanlı koruma açık' } else { 'Gerçek zamanlı koruma başlatılıyor' }) }
            @{ ok = $true; text = "Virüs veritabanı: $sigs" }
            @{ ok = [bool](Get-YaraPaths); text = "Tarama: $engines" }
            $guardCheck
        )
        $status.Invalidate()

        # Sekmeler
        $tabThreat.Text = "Tehditler ($($threats.Count))"
        $tabAdvice.Text = "Önerilerimiz ($($groups.Count))"
        foreach ($pair in @(@($tabThreat, 'threat', $UiLevel.RED), @($tabAdvice, 'advice', $UiAccent))) {
            $tb = $pair[0]; $on = ($state.tab -eq $pair[1])
            $tb.BackColor = if ($on) { $UiSurface2 } else { $UiBg }
            $tb.ForeColor = if ($on) { $UiText } else { $UiMuted }
            $tb.FlatAppearance.BorderColor = if ($on) { $pair[2] } else { [Drawing.Color]::FromArgb(40, 60, 90) }
            $tb.FlatAppearance.BorderSize = if ($on) { 2 } else { 1 }
        }

        if ($state.tab -eq 'threat') {
            $adviceFlow.Visible = $false
            if ($threats) {
                $empty.Visible = $false; $threatFlow.Visible = $true
                # Bulgular degismediyse kartlar yeniden kurulmaz (kaydirma ve ustune gelme korunur)
                $sig = (@($threats | ForEach-Object { "$($_.key)|$($_.level)|$($_.title)|$($_.detail)" }) -join "`n")
                if ($threatFlow.Tag -ne $sig) {
                    $keep = $threatFlow.VerticalScroll.Value
                    $threatFlow.SuspendLayout(); Clear-Flow $threatFlow
                    Add-FindingCards $threatFlow $threats $tips $onDone
                    $threatFlow.ResumeLayout(); $threatFlow.Tag = $sig
                    $threatFlow.AutoScrollPosition = New-Object Drawing.Point(0, $keep)
                }
            } else {
                $threatFlow.Visible = $false; $empty.Visible = $true
                $empty.Text = "✓  Tehdit bulunmadı`n`nCortmed dosyalarınızı arka planda korumaya devam ediyor."
            }
        } else {
            $threatFlow.Visible = $false; $empty.Visible = $false; $adviceFlow.Visible = $true
            $sig = (@($groups | ForEach-Object { "$($_.cat.id)|$($_.cat.text)|" + (@($_.items | ForEach-Object { "$($_.key)|$($_.detail)" }) -join ',') }) -join "`n")
            if ($adviceFlow.Tag -ne $sig) {
                $keep = $adviceFlow.VerticalScroll.Value
                $adviceFlow.SuspendLayout(); Clear-Flow $adviceFlow
                if (-not $groups) {
                    $none = New-Label '✓  Şu an bir önerimiz yok. Her şey yolunda.' 0 0 $UiLevel.OK (New-Font 12 'Bold')
                    $none.Margin = New-Object Windows.Forms.Padding(4, 30, 0, 0)
                    $adviceFlow.Controls.Add($none)
                }
                $w = Get-CardWidth $adviceFlow
                foreach ($grp in $groups) {
                    if ($grp.cat.id -in 'guard-warn', 'guard-history') {
                        # Davranis bekcisi gecmisi: bolum basligi altinda her program kendi kartinda
                        $adviceFlow.Controls.Add((New-SectionHeader $grp.cat.title ($grp.cat.text -f $grp.items.Count) $w))
                        Add-FindingCards $adviceFlow $grp.items $tips $onDone
                    } else {
                        $adviceFlow.Controls.Add((New-AdviceCard $grp $w $tips $runAdvice))
                    }
                }
                $adviceFlow.ResumeLayout(); $adviceFlow.Tag = $sig
                $adviceFlow.AutoScrollPosition = New-Object Drawing.Point(0, $keep)
            }
        }
    }

    $runAdvice = {
        param($grp)
        switch ($grp.cat.id) {
            'protect' {
                $a = [Windows.Forms.MessageBox]::Show(
                    "Windows'un şu korumaları açılacak:`n`n• Zararlı ve dolandırıcı siteleri engelleme`n• İstenmeyen programları engelleme`n• Hesap çalan programlara karşı ek kurallar`n• Güvenlik duvarı`n`nWindows bir onay penceresi gösterecek. Devam edilsin mi?",
                    'Windows korumalarını güçlendir', 'YesNo', 'Question')
                if ($a -ne 'Yes') { return }
                try {
                    $state.harden = Start-Process powershell.exe -Verb RunAs -PassThru -ArgumentList @('-NoProfile', '-ExecutionPolicy', 'Bypass',
                        '-File', ('"{0}"' -f (Join-Path $Root 'Harden.ps1')), '-Auto')
                } catch { }
            }
            'guard' {
                $gp = Start-GuardSetup
                if ($gp) { $state.guardSetup = $gp }
            }
            'updates' { Start-Process 'ms-settings:windowsupdate' }
            'account' { Start-Process 'ms-settings:otherusers' }
            default { Show-FindingList $form $grp.cat.title $grp.items; & $render }
        }
    }

    $startScan = {
        if ($state.scan) { return }
        $state.scan = Start-ScanProcess
        & $render
    }

    $tabThreat.Add_Click({ $state.tab = 'threat'; & $render })
    $tabAdvice.Add_Click({ $state.tab = 'advice'; & $render })
    $btnScan.Add_Click({ & $startScan })
    $btnFile.Add_Click({
        $dlg = New-Object Windows.Forms.OpenFileDialog
        $dlg.Title = 'Kontrol edilecek dosyayı seçin'
        if ($dlg.ShowDialog() -ne 'OK') { return }
        Initialize-Engine
        $form.Cursor = 'WaitCursor'
        $t = Get-FileAnalysis $dlg.FileName
        $form.Cursor = 'Default'
        if ($t.level -eq 'RED') { $t = Resolve-RedFile $t; Add-StatusFinding $t; Raise-Red @($t); & $render }
        [void](Show-Report $form $t)
        & $render
    })
    $btnSettings.Add_Click({ Show-Settings $form; & $render })

    $form.Controls.AddRange(@($content, $tabsBar, $bottom, $status, (New-BrandBar)))
    & $render

    # Arka plandaki tarama ve guclendirme bitince ekrani yenile
    $timer = New-Object Windows.Forms.Timer
    $timer.Interval = 1500
    $tick = @{ n = 0 }
    $timer.Add_Tick({
        $tick.n++
        $changed = $false
        if ($state.scan -and $state.scan.HasExited) { $state.scan = $null; $changed = $true }
        if ($state.harden -and $state.harden.HasExited) { $state.harden = $null; & $startScan }
        # Bekci kurulumu: arayuzu dondurmadan zamanlayicida beklenir, sonuc sade bir notla bildirilir
        if ($state.guardSetup -and $state.guardSetup.HasExited) {
            $code = $null
            try { $code = $state.guardSetup.ExitCode } catch { }
            $state.guardSetup = $null
            & $render
            $note = Get-GuardSetupNote $code
            if ($note) { [Windows.Forms.MessageBox]::Show($form, $note, 'Cortmed Security') | Out-Null }
        }
        if ($changed -or $tick.n % 10 -eq 0) { & $render }
    })
    $timer.Start()
    [void]$form.ShowDialog()
    $panelMutex.ReleaseMutex()
}


# ------------------------------------------------------------------ giris

switch ($Mode) {
    'Panel' { Show-Panel }
    'Watch' { Start-Watcher }
    'Daily' {
        Initialize-Engine
        [void](Update-Database)
        if (Test-ClamReady) { Update-ClamAV }
        [void](Invoke-FullScan)
    }
    'Update' { Initialize-Engine; Update-Database }
    'InstallClamAV' { Install-ClamAV }
    'ScanFile' {
        Initialize-Engine
        (Get-FileAnalysis $Path).report
    }
}
