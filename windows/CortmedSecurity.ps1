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
    if ($s -like 'hata*') { return "Kurulamadı ($s). Kaydet'e basınca tekrar denenir" }
    if (Test-ClamInstalling) { return 'Kuruluyor, birkaç dakika içinde hazır olur' }
    return 'Kurulum yarıda kaldı. Kaydet''e basınca tekrar denenir'
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
function Show-Toast([string]$title, [string]$text, [switch]$Sticky) {
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
function Get-GuardFindings {
    try {
        $file = Join-Path $GuardDataDir 'findings.json'
        if (-not [IO.File]::Exists($file)) { return }
        $items = [IO.File]::ReadAllText($file, [Text.Encoding]::UTF8) | ConvertFrom-Json
        foreach ($i in @($items)) {
            if (-not $i -or -not $i.key -or [string]$i.level -notin 'RED', 'YELLOW') { continue }
            $f = New-Finding ([string]$i.key) ([string]$i.level) ([string]$i.title) ([string]$i.detail) ([string]$i.path)
            $f | Add-Member -NotePropertyName tab -NotePropertyValue 'threat'
            $f | Add-Member -NotePropertyName report -NotePropertyValue ([string]$i.report)
            $f
        }
    } catch { }
}

# Davranis bekcisi durumu. Tepsideki baglanti varsa Sysmon bilgisi ondan, yoksa isaret dosyalari ve hizmetlerden.
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

# Panel durum kartindaki dorduncu kontrol
function Get-GuardCheck($gs) {
    if (-not $gs.installed) { return @{ ok = $false; text = 'Davranış bekçisi kapalı' } }
    if (-not $gs.running) { return @{ ok = $false; text = 'Davranış bekçisi çalışmıyor' } }
    if ($gs.preexisting) { return @{ ok = $false; text = 'Sysmon başka bir ayarla çalışıyor' } }
    if (-not $gs.sysmonOk) { return @{ ok = $false; text = 'Davranış bekçisi tam çalışmıyor' } }
    return @{ ok = $true; text = 'Davranış bekçisi açık' }
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
    $menu.ShowImageMargin = $false
    $menu.BackColor = $UiSurface; $menu.ForeColor = $UiText
    $menu.Font = New-Object Drawing.Font('Segoe UI', 10)
    $miOpen = New-Object Windows.Forms.ToolStripMenuItem 'Cortmed Security''yi aç'
    $miOpen.Font = New-Object Drawing.Font('Segoe UI Semibold', 10)
    $miScan = New-Object Windows.Forms.ToolStripMenuItem 'Şimdi tara'
    $miStop = New-Object Windows.Forms.ToolStripMenuItem 'Korumayı durdur'
    [void]$menu.Items.AddRange(@($miOpen, $miScan, (New-Object Windows.Forms.ToolStripSeparator), $miStop))
    $tray.ContextMenuStrip = $menu

    $state = @{ lastDaily = [datetime]::MinValue; busy = $false; ticks = 0 }
    $prev = Read-Json $StatusPath $null
    if ($prev -and $prev.time) { try { $state.lastDaily = [datetime]$prev.time } catch { } }
    $seen = @{}
    $tries = @{}

    # Davranis bekcisi hizmetine tek baglanti (kendi arka plan okuyucusu var); sorular zamanlayicida alinir
    $guard = @{ client = $null; state = (New-GuardState) }
    try { $guard.client = New-Object Cortmed.GuardClient 'CortmedGuard' } catch { Write-Log "Bekci baglantisi kurulamadi: $_" }
    $guardAnswer = {
        param($id, $decision)
        $c = $guard.client
        if (-not $c -or -not $c.Connected) {
            Show-Toast 'Cortmed Security' 'Koruma hizmetine şu an ulaşılamadı. Birkaç saniye sonra yeniden deneyin.'
            return 'keep'
        }
        $r = $c.Answer($id, $decision)
        Write-Log "Bekci sorusu cevaplandi: $id $decision"
        if ($false -eq $r) {
            Show-Toast 'Cortmed Security' 'Bu program artık çalışmıyor; bir şey yapmanıza gerek yok.'
            return $false
        }
        return $true
    }

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
                try {
                    $pj = $null; $n = 0
                    while ($n -lt 10 -and $guard.client.TryDequeuePrompt([ref]$pj)) { $n++; [void](Show-GuardPrompt $guard.state $pj $guardAnswer) }
                    # 10 dakika cevapsiz: kalici bildirim, pencere kapatildiysa yeniden ac
                    foreach ($id in @(Get-GuardOverdue $guard.state (Get-Date))) {
                        $name = ''
                        try { $name = [string]($guard.state.prompts[$id] | ConvertFrom-Json).program } catch { }
                        $what = if ($name) { "Durdurduğumuz program ($name)" } else { 'Durdurduğumuz program' }
                        Show-Toast 'Cortmed kararınızı bekliyor' "$what hâlâ bekliyor. Açılan pencereden kapatmayı ya da izin vermeyi seçin." -Sticky
                        [void](Show-GuardPrompt $guard.state $guard.state.prompts[$id] $guardAnswer)
                    }
                } catch { Write-Log "Bekci sorusu hatasi: $_" }
            }
            $ready =@($pending.Keys | Where-Object { ((Get-Date) - $pending[$_]).TotalSeconds -ge 1.5 })
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

function New-FlatButton([string]$text, [bool]$primary = $false) {
    $b = New-Object Windows.Forms.Button
    $b.Text = $text; $b.AutoSize = $true; $b.Height = 40
    $b.FlatStyle = 'Flat'; $b.Cursor = 'Hand'
    $b.Padding = New-Object Windows.Forms.Padding(12, 0, 12, 0)
    $b.Margin = New-Object Windows.Forms.Padding(0, 0, 10, 0)
    $b.Font = New-Font 10 'Bold'
    if ($primary) {
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

# Bulgu listesi (tehditler ve "listeyi goster" pencereleri icin ortak)
function New-FindingListView($owner) {
    $list = New-Object Windows.Forms.ListView
    $list.View = 'Details'; $list.FullRowSelect = $true; $list.Dock = 'Fill'; $list.ShowItemToolTips = $true
    $list.BackColor = $UiSurface; $list.ForeColor = $UiText; $list.BorderStyle = 'None'
    $list.HeaderStyle = 'Nonclickable'; $list.OwnerDraw = $true
    $list.Font = New-Font 10
    $list.Add_DrawColumnHeader({
        param($sender, $e)
        $e.Graphics.FillRectangle((New-Object Drawing.SolidBrush $UiSurface2), $e.Bounds)
        $r = New-Object Drawing.RectangleF(($e.Bounds.X + 8), ($e.Bounds.Y + 5), $e.Bounds.Width, $e.Bounds.Height)
        $e.Graphics.DrawString($e.Header.Text, (New-Font 9 'Bold'), (New-Object Drawing.SolidBrush $UiMuted), $r)
    })
    $list.Add_DrawItem({ param($sender, $e) $e.DrawDefault = $false })
    $list.Add_DrawSubItem({
        param($sender, $e)
        $bg = if ($e.Item.Selected) { [Drawing.Color]::FromArgb(30, 64, 104) } else { $UiSurface }
        $e.Graphics.FillRectangle((New-Object Drawing.SolidBrush $bg), $e.Bounds)
        $color = if ($e.ColumnIndex -eq 0) { $e.Item.ForeColor } elseif ($e.ColumnIndex -eq 1) { $UiText } else { $UiMuted }
        $flags = [Windows.Forms.TextFormatFlags]'VerticalCenter, EndEllipsis, SingleLine'
        $rect = New-Object Drawing.Rectangle(($e.Bounds.X + 8), $e.Bounds.Y, ($e.Bounds.Width - 10), $e.Bounds.Height)
        $font = if ($e.ColumnIndex -eq 1) { New-Font 10 'Bold' } else { $sender.Font }
        [Windows.Forms.TextRenderer]::DrawText($e.Graphics, $e.SubItem.Text, $font, $rect, $color, $flags)
    })
    $il = New-Object Windows.Forms.ImageList; $il.ImageSize = New-Object Drawing.Size(1, 32); $list.SmallImageList = $il
    [void]$list.Columns.Add('Durum', 110)
    [void]$list.Columns.Add('Ne bulundu', 300)
    [void]$list.Columns.Add('Ne yapmalı', 440)
    $list.Add_Resize({ param($sender, $e) $sender.Columns[2].Width = [math]::Max(200, $sender.ClientSize.Width - $sender.Columns[0].Width - $sender.Columns[1].Width) })
    return $list
}

function Set-FindingItems($list, $findings) {
    $list.BeginUpdate(); $list.Items.Clear()
    foreach ($f in $findings) {
        $label = if ($f.level -eq 'RED') { '●  Tehlikeli' } elseif ((Get-FindingTab $f) -eq 'threat') { '●  Şüpheli' } else { '●  Bilgi' }
        $item = New-Object Windows.Forms.ListViewItem($label)
        [void]$item.SubItems.Add($f.title); [void]$item.SubItems.Add($f.detail)
        $item.ForeColor = $UiLevel[[string]$f.level]
        $item.ToolTipText = $f.detail
        $item.Tag = $f
        [void]$list.Items.Add($item)
    }
    $list.EndUpdate()
}

# Dosya raporu penceresi. Kullanici dosyaya guvenirse $true dondurur.
function Show-Report($owner, $finding) {
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
    if ($finding.path -and (Test-Path -LiteralPath $finding.path)) {
        $open = New-FlatButton 'Dosyanın klasörünü aç'
        $open.Add_Click({ Start-Process explorer.exe "/select,`"$($finding.path)`"" })
        [void]$bar.Controls.Add($open)
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
    [void]$f.ShowDialog($owner)
    return $result.trusted
}

function Show-FindingList($owner, [string]$title, $findings) {
    $f = New-DarkForm "Cortmed Security - $title" 900 520
    $f.Controls.Add((New-Label 'Ayrıntı için satıra çift tıklayın.' 18 14 $UiMuted (New-Font 9)))
    $wrap = New-Object Windows.Forms.Panel
    $wrap.Location = New-Object Drawing.Point(16, 40); $wrap.Size = New-Object Drawing.Size(852, 420); $wrap.Anchor = 'Top, Bottom, Left, Right'
    $list = New-FindingListView $f
    $list.Add_DoubleClick({
        $sel = $list.SelectedItems
        if ($sel.Count -gt 0 -and $sel[0].Tag) {
            if (Show-Report $f $sel[0].Tag) { $sel[0].Remove() }
        }
    })
    Set-FindingItems $list $findings
    $wrap.Controls.Add($list)
    $f.Controls.Add($wrap)
    [void]$f.ShowDialog($owner)
}

# ------------------------------------------------------------------ davranis bekcisi sorusu

# Acik pencereler, cevaplanan sorular ve ilk gorulme zamanlari (soru kimligine gore)
function New-GuardState {
    return @{ open = @{}; answered = @{}; firstSeen = @{}; reminded = @{}; prompts = @{} }
}

# "Bu program durdurulsun mu" penceresini kurar, gostermez.
# $answer: { param($id, $decision) } -> $false: program artik yok; 'keep': gonderilemedi, pencere acik kalir
function New-GuardPromptForm($prompt, [scriptblock]$answer, $state = $null) {
    $name = [string]$prompt.program
    if (-not $name -and $prompt.path) { $name = Split-Path ([string]$prompt.path) -Leaf }
    if (-not $name) { $name = 'bilinmeyen program' }
    $publisher = if ([string]$prompt.publisher) { [string]$prompt.publisher } else { 'bilinmiyor (imzasız)' }
    $reasons = @($prompt.reasons | Where-Object { $_ } | ForEach-Object { [string]$_ })

    $f = New-DarkForm "Cortmed şüpheli bir programı durdurdu: $name" 640 500
    $f.StartPosition = 'CenterScreen'; $f.TopMost = $true
    $f.FormBorderStyle = 'FixedDialog'; $f.MaximizeBox = $false; $f.MinimizeBox = $false
    $f.Tag = @{ id = [string]$prompt.id; answer = $answer; state = $state; decision = $null; result = $null }

    $head = New-Object Windows.Forms.Label
    $head.Dock = 'Top'; $head.Height = 54; $head.Padding = New-Object Windows.Forms.Padding(16, 0, 0, 0)
    $head.TextAlign = 'MiddleLeft'; $head.Text = 'Şüpheli bir program durduruldu'
    $head.Font = New-Font 13 'Bold'
    $head.ForeColor = [Drawing.Color]::White; $head.BackColor = $UiLevel.RED

    $body = New-Object Windows.Forms.FlowLayoutPanel
    $body.Dock = 'Fill'; $body.FlowDirection = 'TopDown'; $body.WrapContents = $false; $body.AutoScroll = $true
    $body.Padding = New-Object Windows.Forms.Padding(18, 14, 18, 4); $body.BackColor = $UiBg
    $lines = @(
        (New-Label $name 0 0 $UiText (New-Font 12 'Bold') 570)
        (New-Label "Yayıncı: $publisher" 0 0 $UiMuted (New-Font 9.5) 570)
        (New-Label ([string]$prompt.path) 0 0 $UiMuted (New-Font 9) 570)
        (New-Label 'Cortmed bu programı ve başlattığı programları dondurdu. Siz karar verene kadar hiçbir şey yapamaz.' 0 0 $UiText (New-Font 10) 570)
        (New-Label 'Neden durduruldu:' 0 0 $UiText (New-Font 10 'Bold') 570)
    )
    foreach ($r in $reasons) { $lines += New-Label "•  $r" 0 0 $UiText (New-Font 10) 560 }
    foreach ($l in $lines) { $l.Margin = New-Object Windows.Forms.Padding(0, 0, 0, 8); [void]$body.Controls.Add($l) }

    $bar = New-Object Windows.Forms.FlowLayoutPanel
    $bar.Dock = 'Bottom'; $bar.Height = 62; $bar.Padding = New-Object Windows.Forms.Padding(16, 10, 16, 10); $bar.BackColor = $UiBg
    # Dugmeler kapanis degiskeni kullanmaz: bilgi formun ve dugmenin Tag'inde (pencere sonradan tiklanir)
    $onChoice = {
        param($sender, $e)
        $form = $sender.FindForm(); $t = $form.Tag
        if ($t.decision) { return }
        $r = & $t.answer $t.id ([string]$sender.Tag)
        if ($r -is [array]) { $r = $r[-1] }
        if ('keep' -eq $r) { return }
        $t.decision = [string]$sender.Tag; $t.result = $r
        if ($t.state) { $t.state.answered[$t.id] = $true; $t.state.open.Remove($t.id) }
        $form.Close()
    }
    $kill = New-FlatButton 'Programı kapat (önerilen)' $true
    $kill.Tag = 'kill'; $kill.Add_Click($onChoice)
    $allow = New-FlatButton 'İzin ver, devam etsin'
    $allow.Tag = 'allow'; $allow.Add_Click($onChoice)
    $more = New-FlatButton 'Ayrıntılar'
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

# Hizmetten gelen soruyu isler: ayni kimlige ikinci pencere yok, cevaplanan kimlik yok sayilir.
# Kurulan pencereyi dondurur (gosterilmezse -NoShow), aksi halde $null.
function Receive-GuardPrompt($state, [string]$json, [scriptblock]$answer, [switch]$NoShow) {
    $p = $null
    try { $p = $json | ConvertFrom-Json } catch { return $null }
    if (-not $p -or -not $p.PSObject.Properties['id'] -or -not [string]$p.id) { return $null }
    $id = [string]$p.id
    if ($state.answered.ContainsKey($id)) { return $null }
    $old = $state.open[$id]
    if ($old -and -not $old.IsDisposed) { return $null }
    if (-not $state.firstSeen.ContainsKey($id)) { $state.firstSeen[$id] = Get-Date }
    $state.prompts[$id] = $json
    $f = New-GuardPromptForm $p $answer $state
    $state.open[$id] = $f
    if (-not $NoShow) { $f.Show(); $f.Activate() }
    return $f
}

function Show-GuardPrompt($state, [string]$promptJson, [scriptblock]$answer) {
    return Receive-GuardPrompt $state $promptJson $answer
}

# 10 dakikadir cevapsiz sorular; her kimlik icin bir kez doner
function Get-GuardOverdue($state, [datetime]$now) {
    foreach ($id in @($state.firstSeen.Keys)) {
        if ($state.answered.ContainsKey($id) -or $state.reminded.ContainsKey($id)) { continue }
        if (($now - $state.firstSeen[$id]).TotalMinutes -ge 10) { $state.reminded[$id] = $true; $id }
    }
}

# ------------------------------------------------------------------ ayarlar

function Show-Settings($owner) {
    $cfg = Get-Config
    $f = New-DarkForm 'Cortmed Security - Ayarlar' 620 770
    $f.FormBorderStyle = 'FixedDialog'; $f.MaximizeBox = $false; $f.MinimizeBox = $false
    $f.AutoScroll = $true
    $f.Controls.Add((New-Label 'Ayarlar' 22 16 $UiText (New-Font 18 'Bold')))
    $cardW = 560

    function Add-Section([string]$title, [int]$y, [int]$h) {
        $f.Controls.Add((New-Label $title.ToUpper() 24 $y $UiAccent (New-Font 8.5 'Bold')))
        $card = New-Object Windows.Forms.Panel
        $card.Location = New-Object Drawing.Point(20, ($y + 22)); $card.Size = New-Object Drawing.Size($cardW, $h)
        $card.BackColor = $UiSurface
        $f.Controls.Add($card)
        return $card
    }
    function Add-Toggle($card, [string]$title, [string]$desc, [bool]$checked, [int]$y) {
        $cb = New-Object Windows.Forms.CheckBox
        $cb.Text = $title; $cb.Checked = $checked; $cb.AutoSize = $true
        $cb.Font = New-Font 10.5 'Bold'; $cb.ForeColor = $UiText
        $cb.Location = New-Object Drawing.Point(16, $y)
        $card.Controls.Add($cb)
        $card.Controls.Add((New-Label $desc 34 ($y + 26) $UiMuted (New-Font 9) ($cardW - 60)))
        return $cb
    }

    # Koruma
    $sec = Add-Section 'Koruma' 66 168
    $quar = Add-Toggle $sec 'Virüslü dosyaları otomatik karantinaya al' `
        'Kapalıyken Cortmed hiçbir dosyaya dokunmaz, sadece uyarır. Açıkken virüslü dosyalar açılamayacakları bir klasöre taşınır.' ($cfg.autoQuarantine -eq $true) 14
    $clamDesc = 'Arşivlerin ve kurulum dosyalarının içine de bakan üçüncü tarama motoru. İlk açılışta yaklaşık 500 MB indirir.'
    $clamState = Get-ClamStatusText
    if ($cfg.clamav -eq $true -and -not $clamState) { $clamDesc += '  Durum: hazır.' } elseif ($cfg.clamav -eq $true) { $clamDesc += "  Durum: $clamState." }
    $clamBox = Add-Toggle $sec 'Ek tarama motoru (ClamAV)' $clamDesc ($cfg.clamav -eq $true) 90

    # VirusTotal
    $sec = Add-Section 'İkinci görüş (isteğe bağlı)' 262 118
    $sec.Controls.Add((New-Label 'Şüpheli dosyaları 70''ten fazla antivirüs programına sorar. Bunun için ücretsiz bir VirusTotal anahtarı gerekir.' 16 12 $UiMuted (New-Font 9) ($cardW - 32)))
    $vt = New-Object Windows.Forms.TextBox
    $vt.Text = [string]$cfg.vtKey; $vt.Location = New-Object Drawing.Point(16, 54); $vt.Width = $cardW - 32
    $vt.BackColor = $UiSurface2; $vt.ForeColor = $UiText; $vt.BorderStyle = 'FixedSingle'
    $sec.Controls.Add($vt)
    $link = New-Object Windows.Forms.LinkLabel
    $link.Text = 'Ücretsiz anahtar al (virustotal.com)'; $link.AutoSize = $true; $link.Location = New-Object Drawing.Point(16, 86)
    $link.LinkColor = $UiAccent; $link.ActiveLinkColor = $UiText; $link.Font = New-Font 9
    $link.Add_LinkClicked({ Start-Process 'https://www.virustotal.com/gui/join-us' })
    $sec.Controls.Add($link)

    # Veritabani
    $sec = Add-Section 'Virüs veritabanı' 408 128
    $dbText = 'Veritabanı her gün kendiliğinden güncellenir.'
    try { Initialize-Engine; $dbText = ('{0:N0} imza  ·  {1:dd.MM.yyyy} tarihli. Her gün kendiliğinden güncellenir.' -f $script:Db.SignatureCount, ([DateTimeOffset]::FromUnixTimeSeconds($script:Db.BuildTime).LocalDateTime)) } catch { }
    $sec.Controls.Add((New-Label $dbText 16 14 $UiText (New-Font 9.5) ($cardW - 200)))
    $upd = New-FlatButton 'Şimdi güncelle'
    $upd.Location = New-Object Drawing.Point(($cardW - 170), 10); $upd.AutoSize = $false; $upd.Width = 154; $upd.Height = 34
    $upd.Add_Click({
        $f.Cursor = 'WaitCursor'; $r = Update-Database; $f.Cursor = 'Default'
        [Windows.Forms.MessageBox]::Show($(if ($r) { $r } else { 'Güncellenemedi. İnternet bağlantısını ve güncelleme adresini kontrol edin.' }), 'Cortmed Security') | Out-Null
    })
    $sec.Controls.Add($upd)
    $sec.Controls.Add((New-Label 'Gelişmiş: güncelleme adresi' 16 62 $UiMuted (New-Font 8.5)))
    $url = New-Object Windows.Forms.TextBox
    $url.Text = [string]$cfg.updateUrl; $url.Location = New-Object Drawing.Point(16, 84); $url.Width = $cardW - 32
    $url.BackColor = $UiSurface2; $url.ForeColor = $UiMuted; $url.BorderStyle = 'FixedSingle'; $url.Font = New-Font 9
    $sec.Controls.Add($url)

    # Guvenilen dosyalar ve karantina
    $sec = Add-Section 'Güvendiğiniz dosyalar ve karantina' 564 62
    $trustedCount = @($cfg.trustedHashes | Where-Object { $_ }).Count
    $trustLabel = New-Label "$trustedCount dosya güvenilir olarak işaretli." 16 20 $UiText (New-Font 9.5)
    $sec.Controls.Add($trustLabel)
    $reset = New-FlatButton 'Listeyi sıfırla'
    $reset.Location = New-Object Drawing.Point(($cardW - 330), 13); $reset.AutoSize = $false; $reset.Width = 150; $reset.Height = 34
    $reset.Add_Click({
        # Hemen kaydet: Vazgec'e basilsa bile sifirlama gecerli olsun
        $saved = Get-Config; $saved.trustedHashes = @(); Save-Config $saved
        $cfg.trustedHashes = @(); $trustLabel.Text = '0 dosya güvenilir olarak işaretli.'
    })
    $qbtn = New-FlatButton 'Karantina klasörü'
    $qbtn.Location = New-Object Drawing.Point(($cardW - 170), 13); $qbtn.AutoSize = $false; $qbtn.Width = 154; $qbtn.Height = 34
    $qbtn.Add_Click({ Start-Process explorer.exe $QuarantineDir })
    $sec.Controls.AddRange(@($reset, $qbtn))

    $save = New-FlatButton 'Kaydet' $true
    $save.Location = New-Object Drawing.Point(20, 670); $save.AutoSize = $false; $save.Width = 150
    $cancel = New-FlatButton 'Vazgeç'
    $cancel.Location = New-Object Drawing.Point(180, 670); $cancel.AutoSize = $false; $cancel.Width = 120
    $cancel.Add_Click({ $f.Close() })
    $save.Add_Click({
        $cfg.autoQuarantine = $quar.Checked
        $cfg.clamav = $clamBox.Checked
        $cfg.vtKey = $vt.Text.Trim()
        $cfg.updateUrl = $url.Text.Trim()
        Save-Config $cfg
        # Acik ama hazir degilse (ilk acilis ya da yarida kalan kurulum) kurulumu baslat
        if ($cfg.clamav -and -not (Test-ClamReady) -and -not (Test-ClamInstalling)) {
            if (Test-Path $LauncherExe) { [void](Start-Process $LauncherExe -ArgumentList '--mode', 'InstallClamAV') }
            else {
                [void](Start-Process powershell.exe -WindowStyle Hidden -ArgumentList @('-NoProfile', '-ExecutionPolicy', 'Bypass',
                    '-File', ('"{0}"' -f (Join-Path $Root 'CortmedSecurity.ps1')), '-Mode', 'InstallClamAV'))
            }
            [Windows.Forms.MessageBox]::Show('Ek tarama motoru arka planda kuruluyor. İnternet hızınıza göre 5-15 dakika sürer.', 'Cortmed Security') | Out-Null
        }
        $f.Close()
    })
    $f.Controls.AddRange(@($save, $cancel))
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
)

# Davranis bekcisi hizmeti kurulu degilse en uste gelen oneri
$GuardAdvice = @{ id = 'guard'; icon = '🔒'; title = 'Davranış bekçisini açın'
    text = 'Şüpheli davranan programları (örneğin dosyalarınızı şifrelemeye çalışanları) çalışırken durdurur ve size sorar. Windows bir kez izin ister.'
    button = 'Bekçiyi aç' }

function Get-AdviceGroups($advice, [bool]$guardMissing = $false) {
    $groups = @()
    if ($guardMissing) { $groups += [pscustomobject]@{ cat = $GuardAdvice; items = @() } }
    $used = @{}
    foreach ($c in $AdviceCategories) {
        $items = @($advice | Where-Object { ($_.key -split ':')[0] -in $c.prefixes })
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
    $form.Size = New-Object Drawing.Size(940, 700)
    $form.MinimumSize = New-Object Drawing.Size(800, 600)
    $form.StartPosition = 'CenterScreen'
    $form.Font = New-Font 10
    $form.BackColor = $UiBg; $form.ForeColor = $UiText
    $icon = Get-CortmedIcon; if ($icon) { $form.Icon = $icon }
    $tips = New-Object Windows.Forms.ToolTip

    $state = @{ level = 'NONE'; symbol = '…'; title = ''; sub = ''; tab = ''; checks = @(); scan = $null; harden = $null; guardSetup = $null }

    # Durum karti: halka, baslik, aciklama ve alt satirda koruma kontrolleri
    $status = New-Object Windows.Forms.Panel
    $status.Dock = 'Top'; $status.Height = 178; $status.BackColor = $UiBg
    $status.Padding = New-Object Windows.Forms.Padding(16, 14, 16, 6)
    $card = New-Object Windows.Forms.Panel
    $card.Dock = 'Fill'; $card.BackColor = $UiSurface
    $card.GetType().GetProperty('DoubleBuffered', [Reflection.BindingFlags]'NonPublic,Instance').SetValue($card, $true, $null)
    $card.Add_Paint({
        param($sender, $e)
        $g = $e.Graphics
        $g.SmoothingMode = 'AntiAlias'; $g.TextRenderingHint = 'ClearTypeGridFit'
        $c = $UiLevel[$state.level]
        $cx = 28; $cy = 22
        $g.FillEllipse((New-Object Drawing.SolidBrush ([Drawing.Color]::FromArgb(40, $c))), ($cx - 6), ($cy - 6), 104, 104)
        $g.DrawEllipse((New-Object Drawing.Pen ($c, 6)), $cx, $cy, 92, 92)
        $fmt = New-Object Drawing.StringFormat; $fmt.Alignment = 'Center'; $fmt.LineAlignment = 'Center'
        $g.DrawString($state.symbol, (New-Font 30 'Bold'), (New-Object Drawing.SolidBrush $c), (New-Object Drawing.RectangleF($cx, $cy, 92, 92)), $fmt)
        $g.DrawString($state.title, (New-Font 19 'Bold'), (New-Object Drawing.SolidBrush $UiText), 142, 24)
        $g.DrawString($state.sub, (New-Font 10), (New-Object Drawing.SolidBrush $UiMuted),
            (New-Object Drawing.RectangleF(144, 64, ($sender.Width - 160), 44)))
        # Koruma kontrolleri: kullanici neyin calistigini gorsun
        $x = 144; $y = 116
        foreach ($chk in $state.checks) {
            $col = if ($chk.ok) { $UiLevel.OK } else { $UiLevel.YELLOW }
            $txt = $(if ($chk.ok) { '✓ ' } else { '! ' }) + $chk.text
            $tw = [int]$g.MeasureString($txt, (New-Font 9.5 'Bold')).Width
            # Sigmazsa alt satira
            if ($x -gt 144 -and ($x + $tw) -gt ($sender.Width - 12)) { $x = 144; $y += 22 }
            $g.DrawString($txt, (New-Font 9.5 'Bold'), (New-Object Drawing.SolidBrush $col), $x, $y)
            $x += $tw + 22
        }
        $g.FillRectangle((New-Object Drawing.SolidBrush $c), 0, 0, 4, $sender.Height)
    })
    $card.Add_Resize({ $card.Invalidate() })
    $status.Controls.Add($card)

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

    # Icerik: tehdit listesi / bos durum / oneri kartlari
    $content = New-Object Windows.Forms.Panel
    $content.Dock = 'Fill'; $content.Padding = New-Object Windows.Forms.Padding(16, 0, 16, 0); $content.BackColor = $UiBg
    $list = New-FindingListView $form
    $list.Add_DoubleClick({
        $sel = $list.SelectedItems
        if ($sel.Count -gt 0 -and $sel[0].Tag) { if (Show-Report $form $sel[0].Tag) { & $render } }
    })
    $empty = New-Object Windows.Forms.Label
    $empty.Dock = 'Fill'; $empty.TextAlign = 'MiddleCenter'; $empty.BackColor = $UiSurface
    $empty.Font = New-Font 13 'Bold'; $empty.ForeColor = $UiLevel.OK
    $adviceFlow = New-Object Windows.Forms.FlowLayoutPanel
    $adviceFlow.Dock = 'Fill'; $adviceFlow.FlowDirection = 'TopDown'; $adviceFlow.WrapContents = $false
    $adviceFlow.AutoScroll = $true; $adviceFlow.BackColor = $UiBg
    $content.Controls.AddRange(@($list, $empty, $adviceFlow))

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
        $groups = @(Get-AdviceGroups $advice (-not $guardState.installed))

        # Durum karti
        $running = Test-WatcherRunning
        if ($state.scan) {
            $state.level = 'NONE'; $state.symbol = '…'; $state.title = 'Taranıyor…'
            $state.sub = 'Bilgisayarınız taranıyor. Bu birkaç dakika sürebilir; bu sırada bilgisayarınızı kullanmaya devam edebilirsiniz.'
        } elseif (-not $s) {
            $state.level = 'NONE'; $state.symbol = '…'; $state.title = 'İlk tarama bekleniyor'
            $state.sub = 'Cortmed ilk taramayı birkaç dakika içinde kendiliğinden yapacak.'
        } elseif ($sum.reds) {
            $state.level = 'RED'; $state.symbol = '!'; $state.title = 'Dikkat: tehdit bulundu'
            $state.sub = "Bilgisayarınızda $($sum.reds.Count) tehlikeli öğe var. Aşağıdaki listeden ne yapmanız gerektiğini görebilirsiniz."
        } else {
            $state.level = 'OK'; $state.symbol = '✓'; $state.title = 'Bilgisayarınız korunuyor'
            $state.sub = 'Tehdit bulunmadı.'
            if ($sum.time) { $state.sub += '  Son tarama: {0:dd.MM.yyyy HH:mm}.' -f $sum.time }
        }
        $sigs = if ($s -and $s.signatures) { '{0:N0} imza' -f [int]$s.signatures } else { 'hazır' }
        $engines = 'Defender + YARA' + $(if (Test-ClamReady) { ' + ClamAV' } else { '' })
        $state.checks = @(
            @{ ok = $running; text = $(if ($running) { 'Gerçek zamanlı koruma açık' } else { 'Gerçek zamanlı koruma başlatılıyor' }) }
            @{ ok = $true; text = "Virüs veritabanı: $sigs" }
            @{ ok = [bool](Get-YaraPaths); text = "Tarama: $engines" }
            (Get-GuardCheck $guardState)
        )
        $card.Invalidate()

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
                Set-FindingItems $list $threats
                $list.Visible = $true; $empty.Visible = $false
            } else {
                $list.Visible = $false; $empty.Visible = $true
                $empty.Text = "✓  Tehdit bulunmadı`n`nCortmed dosyalarınızı arka planda korumaya devam ediyor."
            }
        } else {
            $list.Visible = $false; $empty.Visible = $false; $adviceFlow.Visible = $true
            $adviceFlow.SuspendLayout()
            $adviceFlow.Controls.Clear()
            if (-not $groups) {
                $none = New-Label '✓  Şu an bir önerimiz yok. Her şey yolunda.' 0 0 $UiLevel.OK (New-Font 12 'Bold')
                $none.Margin = New-Object Windows.Forms.Padding(4, 30, 0, 0)
                $adviceFlow.Controls.Add($none)
            }
            $w = $adviceFlow.ClientSize.Width - 8
            foreach ($grp in $groups) {
                $c = $grp.cat
                $p = New-Object Windows.Forms.Panel
                $p.Size = New-Object Drawing.Size($w, 98); $p.BackColor = $UiSurface
                $p.Margin = New-Object Windows.Forms.Padding(0, 0, 0, 10)
                $bar = New-Object Windows.Forms.Panel
                $bar.Dock = 'Left'; $bar.Width = 4; $bar.BackColor = $UiAccent
                $ico = New-Label $c.icon 18 26 $UiAccent (New-Font 20 'Regular' 'Segoe UI Emoji')
                $ttl = New-Label $c.title 70 16 $UiText (New-Font 11.5 'Bold')
                $txt = New-Label ($c.text -f $grp.items.Count) 70 44 $UiMuted (New-Font 9.5) ($w - 300)
                $btn = New-FlatButton $c.button
                $btn.AutoSize = $false; $btn.Width = 190; $btn.Height = 38
                $btn.Location = New-Object Drawing.Point(($w - 210), 30)
                $btn.Tag = $grp
                $btn.Add_Click({ param($sender, $e) & $runAdvice $sender.Tag })
                $p.Controls.AddRange(@($bar, $ico, $ttl, $txt, $btn))
                $adviceFlow.Controls.Add($p)
            }
            $adviceFlow.ResumeLayout()
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
                $setup = Join-Path $Root 'Install-Guard.ps1'
                if (-not (Test-Path $setup)) {
                    [Windows.Forms.MessageBox]::Show('Davranış bekçisinin kurulum dosyaları bulunamadı. Cortmed Security''yi yeniden kurup tekrar deneyin.', 'Cortmed Security') | Out-Null
                    return
                }
                $a = [Windows.Forms.MessageBox]::Show(
                    "Davranış bekçisi açılacak. Şüpheli davranan bir programı çalışırken durdurur ve ne yapılacağını size sorar.`n`nWindows bir onay penceresi gösterecek. Devam edilsin mi?",
                    'Davranış bekçisini açın', 'YesNo', 'Question')
                if ($a -ne 'Yes') { return }
                # Install-Guard.ps1 kendini yonetici olarak yeniden baslatir (UAC); reddedilirse sessizce biter
                try {
                    $state.guardSetup = Start-Process powershell.exe -WindowStyle Hidden -PassThru -ArgumentList @('-NoProfile', '-ExecutionPolicy', 'Bypass',
                        '-File', ('"{0}"' -f $setup), '-Source', ('"{0}"' -f $Root))
                } catch { }
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
    $adviceFlow.Add_Resize({
        $w = $adviceFlow.ClientSize.Width - 8
        foreach ($p in $adviceFlow.Controls) {
            if ($p -is [Windows.Forms.Panel]) {
                $p.Width = $w
                foreach ($ch in $p.Controls) { if ($ch -is [Windows.Forms.Button]) { $ch.Left = $w - 210 } }
            }
        }
    })

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
        if ($state.guardSetup -and $state.guardSetup.HasExited) { $state.guardSetup = $null; $changed = $true }
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
