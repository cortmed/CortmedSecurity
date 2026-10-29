$ErrorActionPreference = 'Stop'
$root = (Resolve-Path (Join-Path $PSScriptRoot '..\..')).Path
$csc  = Join-Path ([Runtime.InteropServices.RuntimeEnvironment]::GetRuntimeDirectory()) 'csc.exe'
$outDir = Join-Path $env:LOCALAPPDATA 'CortmedBuild\guard-tests'
New-Item -ItemType Directory -Force $outDir | Out-Null
$exe = Join-Path $outDir 'GuardTests.exe'
if (Test-Path $exe) { Remove-Item $exe -Force }

$src = @()
foreach ($d in 'Core', 'Service') {
    $p = Join-Path $root "windows\guard\$d"
    if (Test-Path $p) { $src += (Get-ChildItem $p -Filter *.cs | Sort-Object Name | ForEach-Object FullName) }
}
$src += (Join-Path $root 'windows\CortmedEngine.cs')
$src += (Join-Path $root 'tests\guard\GuardTests.cs')

$refs = 'System.dll','System.Core.dll','System.Xml.dll','System.Xml.Linq.dll','System.ServiceProcess.dll','System.Web.Extensions.dll'
# GuardService.cs kendi Main'ini (GuardProgram) icerir; test calistiricisinin Main'i secilir.
$cscArgs = @('/nologo', '/target:exe', '/main:GuardTests', '/utf8output', '/codepage:65001', "/out:$exe") + ($refs | ForEach-Object { "/r:$_" }) + $src
& $csc @cscArgs
if ($LASTEXITCODE -ne 0) { Write-Host "Derleme hatası"; exit 1 }

& $exe $root
$exeCode = $LASTEXITCODE

# --- Sysmon ayari ve imzali kural yayini kontrolleri ---
$fails = 0
function Check([string]$name, [bool]$ok, [string]$why) {
    if ($ok) { Write-Host "PASS $name" } else { Write-Host "FAIL $name $why"; $script:fails++ }
}

$sysmonPath = Join-Path $root 'windows\guard\sysmon-cortmed.xml'
$xml = $null
try {
    if (-not (Test-Path $sysmonPath)) { throw 'dosya yok' }
    $xml = New-Object System.Xml.XmlDocument
    $xml.Load($sysmonPath)
} catch { $xml = $null; Write-Host "  sysmon xml: $($_.Exception.Message)" }
Check 'sysmon-cortmed.xml gecerli XML' ($xml -ne $null) ''
$sv = $null
if ($xml -ne $null) { $sv = $xml.DocumentElement.GetAttribute('schemaversion') }
Check 'sysmon-cortmed.xml schemaversion' (-not [string]::IsNullOrEmpty($sv)) ''
if ($xml -ne $null) {
    $ids = @($xml.SelectNodes('//RuleGroup/*') | ForEach-Object { $_.LocalName }) -join ','
    foreach ($n in 'ProcessCreate','ProcessTerminate','CreateRemoteThread','ProcessAccess','FileCreate','RegistryEvent') {
        Check "sysmon kural: $n" ($ids -match $n) ''
    }
    # Hepsi-kaydet olaylari bos exclude (yorum dugumleri sayilmaz), digerleri include;
    # tek istisna: FileCreate icin cocuklu bir exclude grubu (gurultu azaltma)
    $logAll = 'ProcessCreate','ProcessTerminate','CreateRemoteThread'
    $bad = @($xml.SelectNodes('//RuleGroup/*') | Where-Object {
        $kids = @($_.ChildNodes | Where-Object { $_.NodeType -eq 'Element' }).Count
        if ($logAll -contains $_.LocalName) { $_.GetAttribute('onmatch') -ne 'exclude' -or $kids -gt 0 }
        elseif ($_.LocalName -eq 'FileCreate' -and $_.GetAttribute('onmatch') -eq 'exclude') { $kids -eq 0 }
        else { $_.GetAttribute('onmatch') -ne 'include' } })
    Check 'sysmon kural bicimi (hepsi=bos exclude, digerleri include)' ($bad.Count -eq 0) ''

    function HasCond([string]$el, [string]$field, [string]$val, [string]$mode) {
        $q = "//RuleGroup/$el[@onmatch='$mode']//$field"
        return (@($xml.SelectNodes($q) | Where-Object { $_.InnerText -eq $val }).Count -gt 0)
    }
    $want = @(
        @('ProcessAccess','TargetImage','\lsass.exe','include'),
        @('FileCreate','TargetFilename','\Start Menu\Programs\Startup\','include'),
        @('FileCreate','TargetFilename','discord_desktop_core','include'),
        @('FileCreate','TargetFilename','\Extensions\','include'),
        @('FileCreate','TargetFilename','\Documents\','include'),
        @('FileCreate','TargetFilename','\Desktop\','include'),
        @('FileCreate','TargetFilename','\Pictures\','include'),
        @('FileCreate','TargetFilename','\Resimler\','include'),
        @('FileCreate','TargetFilename','\Videolar\','include'),
        @('FileCreate','TargetFilename',('\M' + [char]0xFC + 'zik\'),'include'),
        @('FileCreate','TargetFilename','\.vscode\','exclude'),
        @('FileCreate','TargetFilename','\node_modules\','exclude'),
        @('FileCreate','TargetFilename','\.git\','exclude'),
        @('RegistryEvent','TargetObject','\CurrentVersion\Run','include'),
        @('RegistryEvent','TargetObject','\Windows Defender\Exclusions\','include'),
        @('RegistryEvent','TargetObject','DisableRealtimeMonitoring','include'))
    foreach ($w in $want) {
        Check "sysmon $($w[0]) $($w[3]) $($w[2])" (HasCond $w[0] $w[1] $w[2] $w[3]) ''
    }
    # Olay 10: lsass hedefi VE bellek okuma iceren maskeler ayni "and" kuralinda
    $lr = $xml.SelectSingleNode("//RuleGroup/ProcessAccess[@onmatch='include']/Rule[@groupRelation='and']")
    $ga = if ($lr) { $lr.SelectSingleNode("GrantedAccess[@condition='is any']") } else { $null }
    $gaList = if ($ga) { @($ga.InnerText -split ';') } else { @() }
    Check 'sysmon ProcessAccess: lsass + GrantedAccess ayni and kuralinda' ($lr -ne $null -and $lr.SelectSingleNode("TargetImage[.='\lsass.exe']") -ne $null -and $ga -ne $null) ''
    foreach ($m in '0x1010','0x1410','0x1438','0x143a','0x1fffff','0x1f1fff','0x1f3fff','0x10','0x410','0x147a','0x1418','0x1f0fff','0x1038') {
        Check "sysmon GrantedAccess $m" ($gaList -contains $m) ($gaList -join ';')
    }
    Check 'sysmon GrantedAccess 0x1000 (yalniz sorgu) yok' ($gaList -notcontains '0x1000') ''
    Check 'sysmon GrantedAccess 0x40 (VM_READ yok) yok' ($gaList -notcontains '0x40') ''
    $noRead = @($gaList | Where-Object { ([Convert]::ToInt64($_.Substring(2), 16) -band 0x10) -eq 0 })
    Check 'sysmon GrantedAccess: her maske VM_READ (0x10) icerir' ($noRead.Count -eq 0) ($noRead -join ';')
    Check 'sysmon ProcessAccess: kural disi kosul yok' (@($xml.SelectNodes("//RuleGroup/ProcessAccess/*[local-name()!='Rule']")).Count -eq 0) ''
    Check 'sysmon HashAlgorithms SHA256'($xml.DocumentElement.SelectSingleNode('HashAlgorithms').InnerText -eq 'SHA256') ''
    Check 'sysmon genis Windows Defender kurali yok' (-not (HasCond 'RegistryEvent' 'TargetObject' '\Windows Defender\' 'include')) ''
}

$py = Get-Command python -ErrorAction SilentlyContinue
$cryptoOk = $false
if ($py) { & python -c "import cryptography" 2>$null; $cryptoOk = ($LASTEXITCODE -eq 0) }
if (-not $cryptoOk) {
    Write-Host 'SKIP sign_db manifest kontrolu (python veya cryptography yok)'
} else {
    $tmp = Join-Path ([IO.Path]::GetTempPath()) ('cortmed-signtest-' + [Guid]::NewGuid().ToString('N'))
    New-Item -ItemType Directory -Force $tmp | Out-Null
    $savedKey = $env:DB_SIGNING_KEY
    try {
        $keyPath = Join-Path $tmp 'k.pem'
        & python (Join-Path $root 'engine\sign_db.py') --generate $keyPath | Out-Null
        $dist = Join-Path $tmp 'dist'
        New-Item -ItemType Directory -Force $dist | Out-Null
        'test' | Set-Content -Encoding ASCII (Join-Path $dist 'version.txt')
        foreach ($f in 'android.cmdb','windows.cmdb','windows.yarc') { [IO.File]::WriteAllBytes((Join-Path $dist $f), [byte[]](1,2,3)) }
        Copy-Item (Join-Path $root 'engine\rules\android_rules.json') $dist
        Copy-Item (Join-Path $root 'engine\rules\behavior_rules.json') $dist
        $env:DB_SIGNING_KEY = [IO.File]::ReadAllText($keyPath)
        & python (Join-Path $root 'engine\sign_db.py') --dist $dist | Out-Null
        $mp = Join-Path $dist 'manifest.json'
        $has = $false; $shaOk = $false
        if (Test-Path $mp) {
            $m = Get-Content $mp -Raw | ConvertFrom-Json
            $e = $m.files.PSObject.Properties['behavior_rules.json']
            $has = ($e -ne $null)
            if ($has) {
                $h = (Get-FileHash (Join-Path $root 'engine\rules\behavior_rules.json') -Algorithm SHA256).Hash.ToLower()
                $shaOk = ($e.Value.sha256 -eq $h)
            }
        }
        Check 'sign_db manifest behavior_rules.json iceriyor' $has ''
        Check 'sign_db behavior_rules.json sha256 eslesiyor' $shaOk ''
    } catch {
        Check 'sign_db calistirma' $false $_.Exception.Message
    } finally {
        $env:DB_SIGNING_KEY = $savedKey
        Remove-Item $tmp -Recurse -Force -ErrorAction SilentlyContinue
    }
}

# --- sign_db.py davranis kurali denetimi (BehaviorRules.Parse ile ayni kurallar; cryptography gerekmez) ---
if (-not $py) {
    Write-Host 'SKIP sign_db kural denetimi (python yok)'
} else {
    $rt = Join-Path ([IO.Path]::GetTempPath()) ('cortmed-rulecheck-' + [Guid]::NewGuid().ToString('N'))
    New-Item -ItemType Directory -Force $rt | Out-Null
    try {
        $signDb = Join-Path $root 'engine\sign_db.py'
        $rulesPath = Join-Path $root 'engine\rules\behavior_rules.json'
        & python $signDb --check-rules $rulesPath | Out-Null
        Check 'sign_db --check-rules: depodaki kurallar gecerli' ($LASTEXITCODE -eq 0) "kod $LASTEXITCODE"
        $variants = [ordered]@{
            'freezeAt eksik'          = { param($j) $j.PSObject.Properties.Remove('freezeAt') }
            'freezeAt 49'             = { param($j) $j.freezeAt = 49 }
            'freezeAt 201'            = { param($j) $j.freezeAt = 201 }
            'warnAt >= freezeAt'      = { param($j) $j.warnAt = $j.freezeAt }
            'warnAt 19'               = { param($j) $j.warnAt = 19 }
            'windowSeconds 29'        = { param($j) $j.windowSeconds = 29 }
            'massFileCount 1001'      = { param($j) $j.massFileCount = 1001 }
            'massFileSeconds 0'       = { param($j) $j.massFileSeconds = 0 }
            'puan 201'                = { param($j) $j.points.Injection = 201 }
            'puan eksik'              = { param($j) $j.points.PSObject.Properties.Remove('Injection') }
            'neden eksik'             = { param($j) $j.reasons.PSObject.Properties.Remove('LsassAccess') }
            'neverFreeze yalniz ad'   = { param($j) $j.neverFreeze = @('csrss.exe') }
            'neverFreeze eksik'       = { param($j) $j.PSObject.Properties.Remove('neverFreeze') }
            'launchers eksik'         = { param($j) $j.PSObject.Properties.Remove('launchers') }
            'launchers tam yol'       = { param($j) $j.launchers = @('C:\x\a.exe') }
            'syncClients eksik'       = { param($j) $j.PSObject.Properties.Remove('syncClients') }
        }
        $n = 0
        foreach ($name in $variants.Keys) {
            $n++
            $j = Get-Content $rulesPath -Raw -Encoding UTF8 | ConvertFrom-Json
            & $variants[$name] $j
            $f = Join-Path $rt "bad$n.json"
            [IO.File]::WriteAllText($f, ($j | ConvertTo-Json -Depth 6), (New-Object System.Text.UTF8Encoding($false)))
            & python $signDb --check-rules $f | Out-Null
            Check "sign_db --check-rules reddeder: $name" ($LASTEXITCODE -ne 0) "kod $LASTEXITCODE"
        }
        # Imzalama da gecersiz kuralla basarisiz olur ve manifest yazmaz
        $bd = Join-Path $rt 'dist'
        New-Item -ItemType Directory -Force $bd | Out-Null
        Copy-Item (Join-Path $rt 'bad2.json') (Join-Path $bd 'behavior_rules.json')
        $savedKey2 = $env:DB_SIGNING_KEY
        $env:DB_SIGNING_KEY = 'gecersiz'
        try { $so = & python $signDb --dist $bd | Out-String; $sc = $LASTEXITCODE } finally { $env:DB_SIGNING_KEY = $savedKey2 }
        Check 'sign_db gecersiz kuralla imzalamaz' ($sc -ne 0 -and $so -match 'behavior_rules\.json gecersiz' -and -not (Test-Path (Join-Path $bd 'manifest.json'))) "kod $sc $so"
    } catch {
        Check 'sign_db kural denetimi calistirma' $false $_.Exception.Message
    } finally {
        Remove-Item $rt -Recurse -Force -ErrorAction SilentlyContinue
    }
}

# --- Yetkili kurulum ve kaldirma betikleri (yalnizca -WhatIf; yonetici, UAC ve yazma yok) ---
$ig = Join-Path $root 'windows\Install-Guard.ps1'
$ug = Join-Path $root 'windows\Uninstall-Guard.ps1'
foreach ($s in $ig, $ug) {
    $leaf = Split-Path $s -Leaf
    $ok = Test-Path $s
    $why = 'dosya yok'
    if ($ok) {
        $tok = $null; $errs = $null
        [void][System.Management.Automation.Language.Parser]::ParseFile($s, [ref]$tok, [ref]$errs)
        $ok = ($errs.Count -eq 0)
        $why = ($errs | ForEach-Object { $_.Message }) -join '; '
    }
    Check "betik ayristirma: $leaf" $ok $why
    $bom = (Test-Path $s) -and ((@([IO.File]::ReadAllBytes($s) | Select-Object -First 3) -join ',') -eq '239,187,191')
    Check "betik UTF-8 BOM: $leaf" $bom ''
}

$pfBase = if ($env:ProgramW6432) { $env:ProgramW6432 } else { $env:ProgramFiles }
$guardDirs = @((Join-Path $pfBase 'Cortmed'), (Join-Path $env:ProgramData 'Cortmed'))
function DirState { ($guardDirs | ForEach-Object { if (Test-Path $_) { "$_=" + @(Get-ChildItem $_ -Recurse -Force -ErrorAction SilentlyContinue).Count } else { "$_=yok" } }) -join '|' }
$before = DirState
function RunWhatIf([string]$state) {
    if (-not (Test-Path $ig)) { return @('', -1) }
    $o = & powershell.exe -NoProfile -ExecutionPolicy Bypass -File $ig -Source (Join-Path $root 'windows') -WhatIf -SysmonState $state | Out-String
    return @($o, $LASTEXITCODE)
}
$rAbsent = RunWhatIf 'Absent'
$rPresent = RunWhatIf 'Present'
Check 'Install-Guard -WhatIf cikis kodu 0 (Sysmon yok)' ($rAbsent[1] -eq 0) "kod $($rAbsent[1])"
Check 'Install-Guard -WhatIf cikis kodu 0 (Sysmon var)' ($rPresent[1] -eq 0) "kod $($rPresent[1])"
Check 'Install-Guard -WhatIf: Sysmon kurulacak' ($rAbsent[0] -match 'Sysmon kurulacak') $rAbsent[0]
Check 'Install-Guard -WhatIf: Sysmon onceden kurulu' ($rPresent[0] -match ('Sysmon ' + [char]0xF6 + 'nceden kurulu, dokunulmayacak')) $rPresent[0]
Check 'Install-Guard -WhatIf: Sysmon yokken onceden kurulu demez' ($rAbsent[0] -notmatch 'dokunulmayacak') ''
Check 'Install-Guard -WhatIf: hizmet adimi listelenir' ($rAbsent[0] -match 'CortmedGuard') ''
Check 'Install-Guard -WhatIf: kaldirma betigi Program Files''a kopyalanir' ($rAbsent[0] -match 'Uninstall-Guard\.ps1') ''
Check 'Install-Guard -WhatIf: onarim dosyalari Program Files''a kopyalanir' ($rAbsent[0] -match ('Onar' + [char]0x131 + 'm i' + [char]0xE7 + 'in kurulum dosyalar' + [char]0x131)) $rAbsent[0]

# Onarim takimi: Copy-RepairKit gecici klasore; takim kendi basina -Source olarak kullanilabilir (-WhatIf)
$igAst = $null
if (Test-Path $ig) { $t0 = $null; $e0 = $null; $igAst = [System.Management.Automation.Language.Parser]::ParseFile($ig, [ref]$t0, [ref]$e0) }
$rkFn = if ($igAst) { $igAst.FindAll({ param($n) $n -is [System.Management.Automation.Language.FunctionDefinitionAst] -and $n.Name -eq 'Copy-RepairKit' }, $true) | Select-Object -First 1 }
Check 'Install-Guard Copy-RepairKit tanimli' ($rkFn -ne $null) ''
if ($rkFn) {
    . ([ScriptBlock]::Create($rkFn.Extent.Text))
    $kit = Join-Path ([IO.Path]::GetTempPath()) ('cortmed-kit-' + [Guid]::NewGuid().ToString('N'))
    New-Item -ItemType Directory -Force $kit | Out-Null
    try {
        $wsrc = Join-Path $root 'windows'
        $kcs = @(foreach ($d in 'Core', 'Service') { Get-ChildItem (Join-Path $wsrc "guard\$d") -Filter *.cs | ForEach-Object FullName })
        # Eski bir kaynak kalmamali
        New-Item -ItemType Directory -Force (Join-Path $kit 'guard\Core') | Out-Null
        'eski' | Set-Content (Join-Path $kit 'guard\Core\Eski.cs')
        Copy-RepairKit $kit $ig (Join-Path $wsrc 'CortmedEngine.cs') $kcs (Join-Path $wsrc 'guard\sysmon-cortmed.xml') `
            (Join-Path $root 'engine\rules\behavior_rules.json') $ug $null
        $need = @('Install-Guard.ps1', 'CortmedEngine.cs', 'behavior_rules.json', 'Uninstall-Guard.ps1', 'guard\sysmon-cortmed.xml',
            'guard\Core\PathRules.cs', 'guard\Service\GuardEngine.cs')
        $lack = @($need | Where-Object { -not (Test-Path (Join-Path $kit $_)) })
        Check 'onarim takimi: -Source icin gereken dosyalar' ($lack.Count -eq 0) ($lack -join ', ')
        Check 'onarim takimi: eski kaynak silindi' (-not (Test-Path (Join-Path $kit 'guard\Core\Eski.cs'))) ''
        Check 'onarim takimi: kaynak sayisi depoyla ayni' (@(Get-ChildItem (Join-Path $kit 'guard') -Recurse -Filter *.cs).Count -eq $kcs.Count) ''
        $ko = & powershell.exe -NoProfile -ExecutionPolicy Bypass -File (Join-Path $kit 'Install-Guard.ps1') -Source $kit -WhatIf -SysmonState Absent | Out-String
        Check 'onarim takimi -Source olarak calisir (-WhatIf)' ($LASTEXITCODE -eq 0 -and $ko -match 'CortmedGuard') $ko
    } finally { cmd /c rmdir /s /q "$kit" }
}
$igText = if (Test-Path $ig) { Get-Content $ig -Raw -Encoding UTF8 } else { '' }
Check 'Install-Guard: Program Files kaynagi guvenilmezse onarmaz' ($igText -match '\$fromApp -and -not \$appH') ''

$after = DirState
Check 'Install-Guard -WhatIf hicbir sey olusturmaz' ($before -eq $after) "once: $before / sonra: $after"

# Klasor guveni (tutamac tabanli) ve kenara alma: iki betikteki kopyalar ayni, ve gecici klasorde davranis
$fnNames = 'Add-DirTrustType', 'Open-TrustedDir', 'Move-Aside'
function FnTexts([string]$path) {
    $h = @{}
    if (-not (Test-Path $path)) { return $h }
    $t = $null; $e = $null
    $ast = [System.Management.Automation.Language.Parser]::ParseFile($path, [ref]$t, [ref]$e)
    foreach ($f in $ast.FindAll({ param($n) $n -is [System.Management.Automation.Language.FunctionDefinitionAst] }, $true)) {
        if ($fnNames -contains $f.Name) { $h[$f.Name] = $f.Extent.Text }
    }
    return $h
}
$igFns = FnTexts $ig
$ugFns = FnTexts $ug
foreach ($n in $fnNames) {
    Check "$n iki betikte de var ve ayni" ($igFns.ContainsKey($n) -and $ugFns.ContainsKey($n) -and $igFns[$n] -eq $ugFns[$n]) ''
    if ($igFns.ContainsKey($n)) { . ([ScriptBlock]::Create($igFns[$n])) }
}
$loaded = $false
if (-not ($fnNames | Where-Object { -not $igFns.ContainsKey($_) })) {
    try { Add-DirTrustType; $loaded = $true } catch { Write-Host "  Add-DirTrustType: $($_.Exception.Message)" }
}
Check 'guven yardimcisi (C#) derlendi' $loaded ''
if ($loaded) {
    function TrustWhy([string]$p) { $w = $null; $h = [CortmedSetup.DirTrust]::OpenTrusted($p, [ref]$w); if ($h) { $h.Dispose(); return $null }; return $w }
    function SdWhy([string]$sddl) { [CortmedSetup.DirTrust]::CheckDescriptor((New-Object Security.AccessControl.RawSecurityDescriptor $sddl)) }
    # Kural mantigi (SDDL ile): kurulumun verdigi ACL gecer, sapmalar gecmez
    $good = 'O:BAG:SYD:PAI(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;0x1200a9;;;BU)'
    Check 'CheckDescriptor: kurulum ACL''si guvenilir' ($null -eq (SdWhy $good)) (SdWhy $good)
    Check 'CheckDescriptor: SYSTEM sahibi guvenilir' ($null -eq (SdWhy ($good -replace '^O:BA', 'O:SY'))) ''
    Check 'CheckDescriptor: kullanici sahibi guvenilmez' ($null -ne (SdWhy ($good -replace '^O:BA', 'O:BU'))) ''
    Check 'CheckDescriptor: korumasiz DACL guvenilmez' ($null -ne (SdWhy ($good -replace 'D:PAI', 'D:AI'))) ''
    Check 'CheckDescriptor: Users yazma guvenilmez' ($null -ne (SdWhy ($good -replace '0x1200a9;;;BU', '0x1301bf;;;BU'))) ''
    Check 'CheckDescriptor: CREATOR OWNER genel yazma guvenilmez' ($null -ne (SdWhy ($good + '(A;OICIIO;GW;;;CO)'))) ''
    Check 'CheckDescriptor: Everyone WRITE_DAC guvenilmez' ($null -ne (SdWhy ($good + '(A;;WD;;;WD)'))) ''
    Check 'CheckDescriptor: DACL yok guvenilmez' ($null -ne (SdWhy 'O:BAG:SY')) ''

    $tt = Join-Path ([IO.Path]::GetTempPath()) ('cortmed-trust-' + [Guid]::NewGuid().ToString('N'))
    New-Item -ItemType Directory -Force $tt | Out-Null
    try {
        $userDir = Join-Path $tt 'userdir'
        New-Item -ItemType Directory $userDir | Out-Null
        Check 'OpenTrusted: kullanicinin actigi klasor guvenilmez' ($null -ne (TrustWhy $userDir)) ''
        Check 'OpenTrusted: olmayan klasor guvenilmez' ($null -ne (TrustWhy (Join-Path $tt 'yok'))) ''
        # Gercek olumlu ornek: SYSTEM/Administrators sahipli, korumali, kullanicilar yalnizca okur
        $gp = Join-Path ([Environment]::SystemDirectory) 'GroupPolicy'
        $gpOk = (Test-Path $gp) -and ($null -eq (TrustWhy $gp))
        if (Test-Path $gp) { Check 'OpenTrusted: System32\GroupPolicy guvenilir (olumlu ornek)' $gpOk (TrustWhy $gp) }
        else { Write-Host 'SKIP olumlu ornek (System32\GroupPolicy yok)' }
        $jTarget = if ($gpOk) { $gp } else { $userDir }
        $jtop = Join-Path $tt 'jtop'
        cmd /c mklink /J "$jtop" "$jTarget" | Out-Null
        Check "OpenTrusted: guvenilir hedefe junction guvenilmez ($jTarget)" ((Test-Path $jtop) -and ($null -ne (TrustWhy $jtop))) (TrustWhy $jtop)

        # Kenara alma: icinde junction olan klasor tek yeniden adlandirmayla tasinir, hedefe dokunulmaz
        $target = Join-Path $tt 'target'
        New-Item -ItemType Directory $target | Out-Null
        'keep' | Set-Content (Join-Path $target 'keep.txt')
        $victim = Join-Path $tt 'Cortmed'
        New-Item -ItemType Directory $victim | Out-Null
        'a' | Set-Content (Join-Path $victim 'sysmon-installed-by-cortmed')
        cmd /c mklink /J "$(Join-Path $victim 'link')" "$target" | Out-Null
        $aside = $null; $err = ''
        try { $aside = Move-Aside $victim } catch { $err = $_.Exception.Message }
        Check 'Move-Aside: ozgun ad bosaldi' (-not (Test-Path $victim)) $err
        Check 'Move-Aside: .untrusted-<zaman>-<8 hex> adiyla tasindi' ($aside -and $aside -match ([regex]::Escape($victim) + '\.untrusted-\d{14}-[0-9a-f]{8}$') -and (Test-Path (Join-Path $aside 'sysmon-installed-by-cortmed'))) "$aside"
        Check 'Move-Aside: junction hedefine dokunulmadi' ((Test-Path (Join-Path $target 'keep.txt')) -and (Test-Path (Join-Path $aside 'link\keep.txt'))) ''
        $err = ''
        $aside2 = $null
        try { $aside2 = Move-Aside $jtop } catch { $err = $_.Exception.Message }
        Check 'Move-Aside: ust duzey junction''in kendisi tasinir, hedef yerinde' ((-not (Test-Path $jtop)) -and (Test-Path $jTarget) -and $aside2 -and (Test-Path $aside2)) $err

        # Guvenilmeyen veri klasorundeki isarete inanilmaz (-WhatIf, test veri klasoru)
        $fakeData = Join-Path $tt 'data'
        New-Item -ItemType Directory $fakeData | Out-Null
        'x' | Set-Content (Join-Path $fakeData 'sysmon-installed-by-cortmed')
        $o = ''
        if (Test-Path $ig) {
            $o = & powershell.exe -NoProfile -ExecutionPolicy Bypass -File $ig -Source (Join-Path $root 'windows') -WhatIf -SysmonState Present -DataDir $fakeData | Out-String
        }
        Check 'WhatIf: guvenilmeyen klasordeki isaret yok sayilir' ($o -match ('Sysmon ' + [char]0xF6 + 'nceden kurulu, dokunulmayacak') -and $o -notmatch 'Cortmed taraf') $o
        Check 'WhatIf: guvenilmeyen veri klasoru kenara alinip yeniden olusturulacak' ($o -match [regex]::Escape($fakeData) -and $o -match 'untrusted-' -and $o -match 'yeniden olu') $o
        Check 'WhatIf: test veri klasorune dokunulmadi' ((Test-Path (Join-Path $fakeData 'sysmon-installed-by-cortmed')) -and @(Get-ChildItem $tt -Filter 'data.untrusted-*').Count -eq 0) ''
    } finally {
        # Once bilinen baglantilari (yalnizca bagin kendisi, ozyineleme yok) kaldir, sonra agaci sil
        $links = @($jtop, $aside2, (Join-Path $tt 'Cortmed\link'))
        if ($aside) { $links += (Join-Path $aside 'link') }
        foreach ($l in $links) {
            if ($l -and ((Get-Item -LiteralPath $l -Force -ErrorAction SilentlyContinue).Attributes -band [IO.FileAttributes]::ReparsePoint)) { cmd /c rmdir "$l" }
        }
        cmd /c rmdir /s /q "$tt"
    }
}

# Yukseltilmis betikler: ortam degiskeni yolu yok, Remove-Item -Recurse yok, ozyinelemeli yonetici silmesi yok, imzalayan tam eslesme
foreach ($s in $ig, $ug) {
    $txt = if (Test-Path $s) { Get-Content $s -Raw -Encoding UTF8 } else { '$env:' }
    $leaf = Split-Path $s -Leaf
    Check "$leaf ortam degiskeninden yol almaz" ($txt -notmatch '\$env:') ''
    Check "$leaf Remove-Item -Recurse kullanmaz" ($txt -notmatch 'Remove-Item[^\r\n]*-Recurse') ''
    Check "$leaf kullanici icerigi uzerinde ozyinelemeli silme yok" ($txt -notmatch 'Remove-TreeSafe|Remove-EntrySafe|GetFileSystemInfos') ''
}
$igTxt = if (Test-Path $ig) { Get-Content $ig -Raw -Encoding UTF8 } else { '' }
Check 'Install-Guard imzalayan tam eslesme' ($igTxt -match 'GetNameInfo' -and $igTxt -match "-ne 'Microsoft Corporation'" -and $igTxt -notmatch '-like[^\r\n]*Microsoft') ''

# Install-Guard'in kullandigi derleme komutu depo kaynaklariyla derlenir (gecici klasore)
$csc64 = Join-Path $env:windir 'Microsoft.NET\Framework64\v4.0.30319\csc.exe'
$gcsc = if (Test-Path $csc64) { $csc64 } else { Join-Path $env:windir 'Microsoft.NET\Framework\v4.0.30319\csc.exe' }
$gtmp = Join-Path ([IO.Path]::GetTempPath()) ('cortmed-guardbuild-' + [Guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Force $gtmp | Out-Null
try {
    $gexe = Join-Path $gtmp 'CortmedGuard.exe'
    $gsrc = @(Get-ChildItem (Join-Path $root 'windows\guard\Core'), (Join-Path $root 'windows\guard\Service') -Filter *.cs | ForEach-Object FullName) + (Join-Path $root 'windows\CortmedEngine.cs')
    $gargs = @('/nologo', '/target:exe', '/platform:anycpu', '/optimize+', '/codepage:65001', "/out:$gexe") +
        ($refs | ForEach-Object { "/reference:$_" }) + $gsrc
    $gout = & $gcsc @gargs | Out-String
    Check 'CortmedGuard.exe kurulum komutuyla derlenir' (($LASTEXITCODE -eq 0) -and (Test-Path $gexe)) $gout
} finally { Remove-Item $gtmp -Recurse -Force -ErrorAction SilentlyContinue }

# Kullanici betikleri yetkili parcaya baglanir
$inst = Get-Content (Join-Path $root 'windows\Install.ps1') -Raw -Encoding UTF8
$unin = Get-Content (Join-Path $root 'windows\Uninstall.ps1') -Raw -Encoding UTF8
$pkg = Get-Content (Join-Path $root 'make-windows-package.ps1') -Raw -Encoding UTF8
Check 'Install.ps1 Install-Guard.ps1 cagirir' ($inst -match 'Install-Guard\.ps1') ''
Check 'Install.ps1 UAC reddi mesaji' ($inst.Contains('Davran' + [char]0x131 + [char]0x15F + ' bek' + [char]0xE7 + 'isi kurulmad' + [char]0x131 + '; panelden sonra a' + [char]0xE7 + 'abilirsiniz')) ''
Check 'Uninstall.ps1 Program Files kopyasini yukseltir' ($unin -match 'Uninstall-Guard\.ps1' -and $unin -match 'RunAs') ''
foreach ($w in 'Install-Guard.ps1', 'Uninstall-Guard.ps1', 'behavior_rules.json', 'sysmon-cortmed.xml', 'guard\Core', 'guard\Service') {
    Check "paket icerir: $w" ($pkg.Contains($w)) ''
}

# Install.ps1 bekci kurulum dosyalarini kullanici klasorune de kopyalar (panelden sonra acmak icin)
Check 'Install.ps1 bekci kaynaklarini kopyalar (guard Core/Service)' ($inst -match "'Core', 'Service'" -and $inst -match 'guard\\\$d') ''
foreach ($w in 'sysmon-cortmed.xml', 'behavior_rules.json', 'Uninstall-Guard.ps1', 'manifest.sig') {
    Check "Install.ps1 kopyalar: $w" ($inst.Contains($w)) ''
}
Check 'Install.ps1 Install-Guard.ps1''i kullanici klasorune kopyalar' ($inst.Contains('foreach ($f in ''Install-Guard.ps1''')) ''

# --- Tepsi: soru penceresi, bulgular, bekci durumu (ayri powershell, pencere gosterilmez) ---
$secPath = Join-Path $root 'windows\CortmedSecurity.ps1'
$tok = $null; $errs = $null
[void][System.Management.Automation.Language.Parser]::ParseFile($secPath, [ref]$tok, [ref]$errs)
Check 'CortmedSecurity.ps1 ayristirma' ($errs.Count -eq 0) (($errs | ForEach-Object { $_.Message }) -join '; ')
Check 'CortmedSecurity.ps1 UTF-8 BOM' (((@([IO.File]::ReadAllBytes($secPath) | Select-Object -First 3) -join ',') -eq '239,187,191')) ''
$trayOut = & powershell.exe -NoProfile -ExecutionPolicy Bypass -File (Join-Path $PSScriptRoot 'tray-tests.ps1') -RepoRoot $root 2>&1 | ForEach-Object { "$_" }
$trayCode = $LASTEXITCODE
$trayOut | ForEach-Object { Write-Host $_ }
$trayFailLines = @($trayOut | Where-Object { $_ -like 'FAIL *' }).Count
Check 'tepsi testleri (tray-tests.ps1)' ($trayCode -eq 0 -and $trayFailLines -eq 0 -and @($trayOut | Where-Object { $_ -like 'PASS *' }).Count -gt 0) "kod $trayCode, $trayFailLines FAIL"

# --- Zararsiz davranis deneme programi (yalnizca derlenir, ASLA calistirilmaz) ve replay dogrulamasi ---
$btBuild = Join-Path $root 'windows\guard\Test\build-test.ps1'
$btTmp = Join-Path ([IO.Path]::GetTempPath()) ('cortmed-bt-' + [Guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Force $btTmp | Out-Null
try {
    $btExe = Join-Path $btTmp 'CortmedBehaviorTest.exe'
    $btOut = ''
    if (Test-Path $btBuild) { $btOut = & powershell.exe -NoProfile -ExecutionPolicy Bypass -File $btBuild -OutDir $btTmp | Out-String }
    Check 'CortmedBehaviorTest.cs derlenir (calistirilmaz)' ((Test-Path $btBuild) -and ($LASTEXITCODE -eq 0) -and (Test-Path $btExe)) $btOut
    $btSrc = Join-Path $root 'windows\guard\Test\CortmedBehaviorTest.cs'
    $btTxt = if (Test-Path $btSrc) { Get-Content $btSrc -Raw -Encoding UTF8 } else { '' }
    Check 'deneme programi gercek Discord klasorune dokunmaz' ($btTxt -notmatch 'LocalApplicationData|%LOCALAPPDATA%|\\Discord\\' -and $btTxt -match 'CortmedFakeDiscord') ''
    $mpk = Get-Content (Join-Path $root 'make-windows-package.ps1') -Raw -Encoding UTF8
    Check 'paket betigi deneme programini icermez' ($mpk -notmatch 'CortmedBehaviorTest|guard\\Test') ''

    # Replay: derlenmis bekci ile sahte olaylar -> Freeze, tam iki neden, puan >= 80
    $rgExe = Join-Path $btTmp 'CortmedGuard.exe'
    $rgSrc = @(Get-ChildItem (Join-Path $root 'windows\guard\Core'), (Join-Path $root 'windows\guard\Service') -Filter *.cs | ForEach-Object FullName) + (Join-Path $root 'windows\CortmedEngine.cs')
    $rgArgs = @('/nologo', '/target:exe', '/platform:anycpu', '/codepage:65001', "/out:$rgExe") + ($refs | ForEach-Object { "/reference:$_" }) + $rgSrc
    & $gcsc @rgArgs | Out-Null
    Check 'replay icin CortmedGuard.exe derlendi' (($LASTEXITCODE -eq 0) -and (Test-Path $rgExe)) ''
    if (Test-Path $rgExe) {
        $rgData = Join-Path $btTmp 'data'
        New-Item -ItemType Directory -Force $rgData | Out-Null
        $prevEnc = [Console]::OutputEncoding
        [Console]::OutputEncoding = New-Object System.Text.UTF8Encoding($false)
        $rgOut = @(& $rgExe --replay (Join-Path $root 'tests\guard\fixtures\behavior-test') --rules (Join-Path $root 'engine\rules\behavior_rules.json') --data $rgData | ForEach-Object { "$_" })
        $rgCode = $LASTEXITCODE
        [Console]::OutputEncoding = $prevEnc
        $fz = @($rgOut | Where-Object { $_ -like 'Freeze *' })
        Check 'replay cikis kodu 0' ($rgCode -eq 0) "kod $rgCode"
        Check 'replay tam bir Freeze karari verir' ($fz.Count -eq 1) ($rgOut -join ' / ')
        if ($fz.Count -eq 1) {
            $line = $fz[0]
            $score = if ($line -match 'puan=(\d+)') { [int]$Matches[1] } else { -1 }
            $reasons = @(($line -split ' \| ', 2)[1] -split '; ')
            Check 'replay puan >= 80' ($score -ge 80) $line
            Check 'replay tam iki neden' ($reasons.Count -eq 2) $line
            $c = @{ a = [char]0xE7; i = [char]0x131; s = [char]0x15F; g = [char]0x11F; B = [char]0x15E; o = [char]0xF6; u = [char]0xFC }
            $want1 = "Kendini a$($c.a)$($c.i)l$($c.i)$($c.s)a eklemeye $($c.a)al$($c.i)$($c.s)t$($c.i)."
            $want2 = "Ba$($c.s)ka bir program$($c.i)n (Discord/taray$($c.i)c$($c.i)) dosyalar$($c.i)n$($c.i) de$($c.g)i$($c.s)tirmeye $($c.a)al$($c.i)$($c.s)t$($c.i)."
            Check 'replay nedeni: Persistence' ($reasons.Count -ge 1 -and $reasons[0] -eq $want1) $line
            Check 'replay nedeni: TamperOtherApp' ($reasons.Count -eq 2 -and $reasons[1] -eq $want2) $line
        }

        # Edge'in indirme cubugundan acilan deneme programi: kok program olur, Edge degil
        [Console]::OutputEncoding = New-Object System.Text.UTF8Encoding($false)
        $reOut = @(& $rgExe --replay (Join-Path $root 'tests\guard\fixtures\behavior-test-edge') --rules (Join-Path $root 'engine\rules\behavior_rules.json') --data $rgData | ForEach-Object { "$_" })
        $reCode = $LASTEXITCODE
        [Console]::OutputEncoding = $prevEnc
        $efz = @($reOut | Where-Object { $_ -like 'Freeze *' })
        Check 'replay (Edge) cikis kodu 0' ($reCode -eq 0) "kod $reCode"
        Check 'replay (Edge) tam bir Freeze, kok deneme programi' ($efz.Count -eq 1 -and $efz[0] -match 'k.k=7000 ' -and $efz[0] -match '\\Downloads\\CortmedBehaviorTest\.exe \|') ($reOut -join ' / ')
        Check 'replay (Edge) hicbir karar Edge''i adlandirmaz' (@($reOut | Where-Object { $_ -match 'msedge' }).Count -eq 0) ($reOut -join ' / ')
    }
} finally { Remove-Item $btTmp -Recurse -Force -ErrorAction SilentlyContinue }

# --- Tarayici eklentisi cekirdek testleri (Edge headless) ---
$edge = $null
foreach ($pf in ${env:ProgramFiles(x86)}, $env:ProgramFiles) {
    if ($pf) { $c = Join-Path $pf 'Microsoft\Edge\Application\msedge.exe'; if (Test-Path $c) { $edge = $c; break } }
}
if (-not $edge) { Write-Host 'SKIP eklenti cekirdek testleri (Edge yok)' }
else {
    # file:// sanal zamanda WebCrypto'yu bekletmez; 127.0.0.1 uzerinden sunulur, /hold sanal zamani durdurur.
    $bdTmp = Join-Path $env:TEMP ('cortmed-edge-' + [guid]::NewGuid().ToString('N'))
    $lis = $null; $bdPort = 0
    for ($try = 0; $try -lt 3 -and -not $lis; $try++) {
        $tcp = New-Object Net.Sockets.TcpListener([Net.IPAddress]::Loopback, 0); $tcp.Start()
        $bdPort = $tcp.LocalEndpoint.Port; $tcp.Stop()
        $cand = New-Object Net.HttpListener
        $cand.Prefixes.Add("http://127.0.0.1:$bdPort/")
        try { $cand.Start(); $lis = $cand } catch { try { $cand.Close() } catch {} }
    }
    $bdPages = @(
        @{ Name = 'eklenti cekirdek ve arka plan testleri (Edge)'; Path = 'tests/test.html' },
        @{ Name = 'eklenti icerik betigi testleri (Edge)'; Path = 'tests/login-fixture.html' }
    )
    if (-not $lis) { foreach ($pg in $bdPages) { Check $pg.Name $false 'HttpListener baslatilamadi' } }
    else {
        $bdBase = Join-Path $root 'browser'
        # Tek bekleyen BeginGetContext sayfalar arasinda paylasilir; yoksa onceki sayfadan kalan istek ilk istegi yutar.
        $ar = $lis.BeginGetContext($null, $null)
        try {
            foreach ($pg in $bdPages) {
                $bdProc = $null
                $pgTmp = "$bdTmp-" + [IO.Path]::GetFileNameWithoutExtension($pg.Path)
                try {
                    $bdArgs = '--headless=new', '--disable-gpu', '--no-first-run', '--disable-background-networking', '--disable-component-update', '--disable-sync', "--user-data-dir=$pgTmp", '--virtual-time-budget=5000', '--dump-dom', "http://127.0.0.1:$bdPort/$($pg.Path)"
                    $bdProc = Start-Process $edge -ArgumentList $bdArgs -RedirectStandardOutput "$pgTmp.out" -RedirectStandardError "$pgTmp.err" -PassThru -WindowStyle Hidden
                    $sw = [Diagnostics.Stopwatch]::StartNew()
                    while (-not $bdProc.HasExited -and $sw.Elapsed.TotalSeconds -lt 60) {
                        if (-not $ar.AsyncWaitHandle.WaitOne(50)) { continue }
                        try {
                            $ctx = $lis.EndGetContext($ar)
                        } catch { $ar = $lis.BeginGetContext($null, $null); continue }
                        $ar = $lis.BeginGetContext($null, $null)
                        try {
                            $rel = [Uri]::UnescapeDataString($ctx.Request.Url.AbsolutePath).TrimStart('/') -replace '/', '\'
                            $file = Join-Path $bdBase $rel
                            $bytes = [byte[]]@()
                            if ($rel -eq 'hold') { Start-Sleep -Milliseconds 300 }
                            elseif ($rel -notmatch '\.\.' -and (Test-Path -LiteralPath $file -PathType Leaf)) {
                                $bytes = [IO.File]::ReadAllBytes($file)
                                $ctx.Response.ContentType = switch -Wildcard ($rel) {
                                    '*.js'   { 'text/javascript; charset=utf-8' }
                                    '*.json' { 'application/json; charset=utf-8' }
                                    '*.png'  { 'image/png' }
                                    '*.txt'  { 'text/plain; charset=utf-8' }
                                    '*.css'  { 'text/css; charset=utf-8' }
                                    default  { 'text/html; charset=utf-8' }
                                }
                            } else { $ctx.Response.StatusCode = 404 }
                            $ctx.Response.OutputStream.Write($bytes, 0, $bytes.Length); $ctx.Response.Close()
                        } catch { try { $ctx.Response.Abort() } catch {} }
                    }
                    if (-not $bdProc.HasExited) { & taskkill /PID $bdProc.Id /T /F 2>&1 | Out-Null }
                    $bdProc.WaitForExit(10000) | Out-Null
                    $bdOut = if (Test-Path -LiteralPath "$pgTmp.out") { (Get-Content -LiteralPath "$pgTmp.out" -Raw -Encoding UTF8) } else { '' }
                    $m = [regex]::Match("$bdOut", 'id="result">([^<]*)')
                    Check $pg.Name ("$bdOut" -match 'id="result">PASS') $m.Groups[1].Value
                    if ($m.Success) { Write-Host "  $($pg.Path): $($m.Groups[1].Value)" }
                } finally {
                    if ($bdProc -and -not $bdProc.HasExited) {
                        & taskkill /PID $bdProc.Id /T /F 2>&1 | Out-Null
                        $bdProc.WaitForExit(10000) | Out-Null
                    }
                    Remove-Item -LiteralPath $pgTmp, "$pgTmp.out", "$pgTmp.err" -Recurse -Force -ErrorAction SilentlyContinue
                }
            }
        } finally {
            try { $lis.Close() } catch {}
        }
    }
}

# --- Tarayici koprusu (CortmedBrowserHost.exe): Chrome stdio protokolu, yol dogrulama, sahte tarama komutu ---
# Kayit defterine yazilmaz; kopru gecici klasore derlenir, gercek tarama yerine sahte betik kullanilir.
function QuoteArg([string]$a) {
    if ($a -and $a -notmatch '[\s"]') { return $a }
    $s = [regex]::Replace($a, '(\\*)"', { param($m) $m.Groups[1].Value + $m.Groups[1].Value + '\"' })
    $s = [regex]::Replace($s, '(\\+)$', { param($m) $m.Groups[1].Value + $m.Groups[1].Value })
    return '"' + $s + '"'
}
function New-HostFrame([string]$json) {
    $b = [Text.Encoding]::UTF8.GetBytes($json)
    return [byte[]]([BitConverter]::GetBytes([int]$b.Length) + $b)
}
# Kopruye bir cerceve yazar, cerceveli yaniti okur. -KeepOpen: stdin acik kalir (govdeyi okumaya kalkarsa takilir).
function Invoke-BrowserHost([string]$hostExe, [string[]]$hostArgs, [byte[]]$frame, [switch]$KeepOpen, [int]$TimeoutMs = 60000) {
    $psi = New-Object Diagnostics.ProcessStartInfo $hostExe
    $psi.Arguments = (@($hostArgs) | ForEach-Object { QuoteArg $_ }) -join ' '
    $psi.UseShellExecute = $false; $psi.CreateNoWindow = $true
    $psi.RedirectStandardInput = $true; $psi.RedirectStandardOutput = $true; $psi.RedirectStandardError = $true
    # stdin StreamWriter'i Console.InputEncoding ile kurulur; BOM'lu UTF-8 ise cercevenin onune BOM yazar (Chrome yazmaz)
    $prevIn = [Console]::InputEncoding
    [Console]::InputEncoding = New-Object System.Text.UTF8Encoding($false)
    try { $p = [Diagnostics.Process]::Start($psi) } finally { [Console]::InputEncoding = $prevIn }
    $errTask = $p.StandardError.ReadToEndAsync()
    $ms = New-Object IO.MemoryStream
    $copy = $p.StandardOutput.BaseStream.CopyToAsync($ms)
    $inS = $p.StandardInput.BaseStream
    if ($KeepOpen) {
        # Yalnizca kucuk cerceve (baslik); stdin acik kalir
        try { $inS.Write($frame, 0, $frame.Length); $inS.Flush() } catch { }
    } else {
        $wr = $null
        try { $wr = $inS.WriteAsync($frame, 0, $frame.Length) } catch { }
        try { if ($wr) { [void]$wr.Wait(5000) }; $inS.Flush(); $p.StandardInput.Close() } catch { }
    }
    $exited = $p.WaitForExit($TimeoutMs)
    if (-not $exited) { try { $p.Kill() } catch { }; [void]$p.WaitForExit(10000) }
    try { [void]$copy.Wait(10000) } catch { }
    try { $p.StandardInput.Close() } catch { }
    $bytes = $ms.ToArray()
    $r = [pscustomobject]@{ exited = $exited; code = $(if ($exited) { $p.ExitCode } else { -1 }); framed = $false; reply = $null; raw = ''; err = '' }
    try { if ($errTask.Wait(5000)) { $r.err = $errTask.Result } } catch { }
    if ($bytes.Length -ge 4) {
        $len = [BitConverter]::ToInt32($bytes, 0)
        $r.framed = ($len -eq $bytes.Length - 4)
        $r.raw = [Text.Encoding]::UTF8.GetString($bytes, 4, $bytes.Length - 4)
        try { $r.reply = $r.raw | ConvertFrom-Json } catch { }
    }
    return $r
}
function Test-HostError($r, [string[]]$titles) {
    return ($r.exited -and $r.code -eq 0 -and $r.framed -and $r.reply -and $r.reply.level -ceq 'ERROR' -and @($r.reply.reasons).Count -eq 0 -and
        $titles -ccontains [string]$r.reply.title)
}
$tBad = 'Geçersiz dosya yolu'; $tOut = 'Bu konumdaki dosyalar taranmaz'; $tMiss = 'Dosya bulunamadı'; $tReq = 'İstek okunamadı'
$tSize = 'İstek çok büyük ya da boş'; $tOutput = 'Tarama sonucu okunamadı'; $tFailed = 'Dosya taranamadı'
function HostWhy($r) { return "exited=$($r.exited) code=$($r.code) framed=$($r.framed) raw=$($r.raw) err=$($r.err)" }

$hostSrc = Join-Path $root 'windows\browser\CortmedBrowserHost.cs'
$hostTpl = Join-Path $root 'windows\browser\com.cortmed.security.json.template'
$tplOk = $false
try {
    $tplTxt = [IO.File]::ReadAllText($hostTpl)
    $tpl = $tplTxt | ConvertFrom-Json
    $tplOk = ($tpl.name -eq 'com.cortmed.security' -and $tpl.type -eq 'stdio' -and $tpl.path -eq '__HOST_PATH__' -and
        @($tpl.allowed_origins).Count -eq 1 -and $tpl.allowed_origins[0] -eq 'chrome-extension://__EXTENSION_ID__/')
} catch { }
Check 'kopru bildirim sablonu (com.cortmed.security.json.template)' $tplOk ''

$hTmp = Join-Path ([IO.Path]::GetTempPath()) ('cortmed-hosttest-' + [Guid]::NewGuid().ToString('N'))
$hFileDir = Join-Path $env:TEMP 'cortmed host test ü'
New-Item -ItemType Directory -Force $hTmp | Out-Null
try {
    $hExe = Join-Path $hTmp 'CortmedBrowserHost.exe'
    $hOut = ''
    if (Test-Path $hostSrc) {
        $hArgs = @('/nologo', '/target:exe', '/platform:anycpu', '/optimize+', '/codepage:65001', "/out:$hExe", '/reference:System.Web.Extensions.dll', $hostSrc)
        $hOut = & $gcsc @hArgs | Out-String
    }
    Check 'CortmedBrowserHost.cs derlenir (C# 5, csc v4)' ((Test-Path $hostSrc) -and ($LASTEXITCODE -eq 0) -and (Test-Path $hExe)) $hOut
    $hostSrcTxt = if (Test-Path $hostSrc) { Get-Content $hostSrc -Raw -Encoding UTF8 } else { '' }
    Check 'kopru PATH''e guvenmez (System32 powershell, -NonInteractive)' ($hostSrcTxt -match 'Environment\.SystemDirectory' -and $hostSrcTxt -match 'WindowsPowerShell' -and $hostSrcTxt -match '"-NonInteractive"') ''

    # Yeniden ayristirma etiketi karari: yalnizca bulut ailesi (OneDrive) kabul, digerleri ret
    $tagWhy = 'derlenemedi'
    try {
        if (-not ('Cortmed.Browser.BrowserHost' -as [type])) {
            Add-Type -AssemblyName System.Web.Extensions
            Add-Type -TypeDefinition $hostSrcTxt -ReferencedAssemblies ([System.Web.Script.Serialization.JavaScriptSerializer].Assembly.Location)
        }
        $tagBad = @(@('9000001A', '9000101A', '9000F01A') | Where-Object { -not [Cortmed.Browser.BrowserHost]::IsAllowedReparseTag([Convert]::ToUInt32($_, 16)) }) +
            @(@('A000000C', 'A0000003', '8000001B') | Where-Object { [Cortmed.Browser.BrowserHost]::IsAllowedReparseTag([Convert]::ToUInt32($_, 16)) })
        $tagWhy = if ($tagBad.Count -eq 0) { '' } else { 'yanlis: ' + ($tagBad -join ',') }
    } catch { $tagWhy = $_.Exception.Message }
    Check 'kopru: reparse etiketi (bulut kabul; symlink/junction/dedup ret)' ($tagWhy -eq '') $tagWhy
    Check 'kopru kayit defterine dokunmaz' ($hostSrcTxt -notmatch 'Microsoft\.Win32|Registry') ''

    # Sahte tarama komutu: -Kind'a gore sabit cikti verir, aldigi -Path'i -Log dosyasina yazar
    $stub = Join-Path $hTmp 'stub.ps1'
    $stubTxt = @'
param([string]$Kind, [string]$Log, [string]$Path)
[Console]::OutputEncoding = New-Object System.Text.UTF8Encoding($false)
if ($Log) { [IO.File]::WriteAllText($Log, $Path, (New-Object System.Text.UTF8Encoding($false))) }
switch ($Kind) {
    'ok' { [Console]::Out.WriteLine('once gelen gurultu'); [Console]::Out.WriteLine('{"level":"OK","title":"t","reasons":[]}'); [Console]::Out.WriteLine('') }
    'garbage' { [Console]::Out.WriteLine('bu bir JSON degil {') }
    'pwned' { [Console]::Out.WriteLine('{"level":"PWNED","title":"x","reasons":["y"]}') }
    'tr' {
        $o = [ordered]@{ level = 'YELLOW'; title = ('Şüpheli dosya: ' + ('ç' * 300)); reasons = @('ı1', 'ğ2', 'ş3', 'ö4', 'ü5', 'İ6', 7, ('x' * 300)) }
        [Console]::Out.WriteLine(($o | ConvertTo-Json -Compress))
    }
    'hang' {
        # Kendi alt surecini baslatir (stdout borusunu miras alir) ve bekler: zaman asiminda ikisi de kapanmali
        $psi = New-Object System.Diagnostics.ProcessStartInfo (Join-Path ([Environment]::SystemDirectory) 'PING.EXE'), '-n 120 127.0.0.1'
        $psi.UseShellExecute = $false; $psi.CreateNoWindow = $true
        $c = [System.Diagnostics.Process]::Start($psi)
        [IO.File]::WriteAllText("$Log.pid", [string]$c.Id)
        Start-Sleep -Seconds 120
    }
}
[Console]::Out.Flush()
'@
    [IO.File]::WriteAllText($stub, $stubTxt, (New-Object Text.UTF8Encoding($true)))
    $psExe = Join-Path ([Environment]::SystemDirectory) 'WindowsPowerShell\v1.0\powershell.exe'
    $stubLog = Join-Path $hTmp 'stub-path.txt'
    # Kopru secenekleri --scan-cmd'den once gelir (--scan-cmd sonrasi tarama komutunun argumanlaridir)
    function StubArgs([string]$data, [string]$kind, [string[]]$extra = @()) { return @('--data', $data) + @($extra) + @('--scan-cmd', $psExe, '-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', $stub, '-Kind', $kind, '-Log', $stubLog) }
    function PathFrame([string]$p) { return (New-HostFrame (@{ path = $p } | ConvertTo-Json -Compress)) }

    if (Test-Path $hExe) {
        $d1 = Join-Path $hTmp 'data-missing'
        $r = Invoke-BrowserHost $hExe (StubArgs $d1 'ok') (PathFrame (Join-Path $hTmp 'yok.exe'))
        Check 'kopru: olmayan dosya -> ERROR' (Test-HostError $r $tMiss) (HostWhy $r)
        Check 'kopru: hatali yolda da browser-lastseen.txt yazilir' (Test-Path (Join-Path $d1 'browser-lastseen.txt')) ''

        $r = Invoke-BrowserHost $hExe (StubArgs (Join-Path $hTmp 'd2') 'ok') (PathFrame 'C:\Windows\notepad.exe')
        Check 'kopru: profil disi (notepad.exe) -> ERROR' (Test-HostError $r $tOut) (HostWhy $r)

        $up = [Environment]::GetFolderPath('UserProfile')
        $badPaths = @(
            (Join-Path $up '..\..\Windows\notepad.exe'),
            ('\\?\' + (Join-Path $hTmp 'stub.ps1')),
            ('\\.\' + (Join-Path $hTmp 'stub.ps1')),
            '\\127.0.0.1\c$\Windows\notepad.exe',
            'stub.ps1',
            ($stub + ':gizli'),
            (Join-Path $hTmp 'stu?.ps1'),
            (Join-Path $hTmp '*.ps1'),
            ''
        )
        foreach ($bp in $badPaths) {
            $r = Invoke-BrowserHost $hExe (StubArgs (Join-Path $hTmp 'd3') 'ok') (PathFrame $bp)
            Check "kopru: gecersiz yol reddedilir [$bp]" (Test-HostError $r @($tBad, $tOut)) (HostWhy $r)
        }

        $big = [byte[]][BitConverter]::GetBytes([int]70000)
        $r = Invoke-BrowserHost $hExe (StubArgs (Join-Path $hTmp 'd4') 'ok') $big -KeepOpen -TimeoutMs 15000
        Check 'kopru: 70000 baytlik baslik -> ERROR ve govdeyi okumadan cikar' (Test-HostError $r $tSize) (HostWhy $r)
        $r = Invoke-BrowserHost $hExe (StubArgs (Join-Path $hTmp 'd4') 'ok') ([byte[]](0, 0, 0, 0)) -KeepOpen -TimeoutMs 15000
        Check 'kopru: 0 uzunluk -> ERROR' (Test-HostError $r $tSize) (HostWhy $r)

        $r = Invoke-BrowserHost $hExe (StubArgs (Join-Path $hTmp 'd5') 'ok') (New-HostFrame '{"path":')
        Check 'kopru: bozuk JSON -> ERROR' (Test-HostError $r $tReq) (HostWhy $r)
        $r = Invoke-BrowserHost $hExe (StubArgs (Join-Path $hTmp 'd5') 'ok') (New-HostFrame '{"path":5}')
        Check 'kopru: path metin degil -> ERROR' (Test-HostError $r $tReq) (HostWhy $r)
        $r = Invoke-BrowserHost $hExe (StubArgs (Join-Path $hTmp 'd5') 'ok') (New-HostFrame '{"cmd":"calc"}')
        Check 'kopru: path yok -> ERROR' (Test-HostError $r $tReq) (HostWhy $r)

        New-Item -ItemType Directory -Force $hFileDir | Out-Null
        $qf = Join-Path $hFileDir 'a"b.exe'
        $r = Invoke-BrowserHost $hExe (StubArgs (Join-Path $hTmp 'd6') 'ok') (PathFrame $qf)
        Check 'kopru: tirnak iceren yol -> ERROR' (Test-HostError $r $tBad) (HostWhy $r)

        $vf = Join-Path $hFileDir 'a b.exe'
        [IO.File]::WriteAllBytes($vf, [byte[]](77, 90))
        $d7 = Join-Path $hTmp 'data-ok'
        Remove-Item $stubLog -Force -ErrorAction SilentlyContinue
        $r = Invoke-BrowserHost $hExe (StubArgs $d7 'ok') (PathFrame $vf)
        $want = '{"level":"OK","title":"t","reasons":[]}'
        $got = if ($r.reply) { $r.reply | ConvertTo-Json -Compress } else { '' }
        Check 'kopru: gecerli dosya -> sahte taramanin JSON''u aynen' ($r.exited -and $r.framed -and $r.code -eq 0 -and $got -eq $want) ("got=$got " + (HostWhy $r))
        $seen = Join-Path $d7 'browser-lastseen.txt'
        $seenOk = $false
        if (Test-Path $seen) { $st = (Get-Content $seen -Raw).Trim(); $dt = [datetime]::MinValue; $seenOk = [datetime]::TryParse($st, [Globalization.CultureInfo]::InvariantCulture, [Globalization.DateTimeStyles]::AdjustToUniversal, [ref]$dt) -and $st -match 'Z$' -and ([datetime]::UtcNow - $dt).TotalMinutes -lt 10 }
        Check 'kopru: browser-lastseen.txt yazildi (ISO UTC)' $seenOk ''
        $logged = if (Test-Path $stubLog) { [IO.File]::ReadAllText($stubLog, [Text.Encoding]::UTF8) } else { '' }
        Check 'kopru: tarama komutuna yol bozulmadan gecer (bosluk, u-umlaut)' ($logged -eq $vf) "log=$logged"

        $r = Invoke-BrowserHost $hExe (StubArgs (Join-Path $hTmp 'd8') 'garbage') (PathFrame $vf)
        Check 'kopru: anlamsiz tarama ciktisi -> ERROR' (Test-HostError $r $tOutput) (HostWhy $r)
        $r = Invoke-BrowserHost $hExe (StubArgs (Join-Path $hTmp 'd8') 'pwned') (PathFrame $vf)
        Check 'kopru: level PWNED -> ERROR' (Test-HostError $r $tFailed) (HostWhy $r)
        $r = Invoke-BrowserHost $hExe (StubArgs (Join-Path $hTmp 'd8') 'tr') (PathFrame $vf)
        $trOk = $r.framed -and $r.reply -and $r.reply.level -eq 'YELLOW' -and ([string]$r.reply.title).StartsWith('Şüpheli dosya: ç') -and
            ([string]$r.reply.title).Length -eq 200 -and @($r.reply.reasons).Count -eq 5 -and (@($r.reply.reasons) -join ',') -ceq 'ı1,ğ2,ş3,ö4,ü5'
        Check 'kopru: Turkce karakterler korunur, baslik 200, en fazla 5 neden' $trOk (HostWhy $r)

        # Kisa govde (baslik 100, yalnizca 10 bayt) ve bos stdin
        $short = [byte[]]([BitConverter]::GetBytes([int]100) + [byte[]](1..10))
        $r = Invoke-BrowserHost $hExe (StubArgs (Join-Path $hTmp 'd9') 'ok') $short
        Check 'kopru: kisa govde -> ERROR' (Test-HostError $r $tReq) (HostWhy $r)
        $r = Invoke-BrowserHost $hExe (StubArgs (Join-Path $hTmp 'd9') 'ok') ([byte[]]@())
        Check 'kopru: bos stdin -> ERROR' (Test-HostError $r $tReq) (HostWhy $r)

        # Kabuk karakterli ad tek ve harfi harfine arguman olarak gecer
        $odd = Join-Path $hFileDir '-Mode Lib $(x) & '';''.exe'
        [IO.File]::WriteAllBytes($odd, [byte[]](77, 90))
        Remove-Item $stubLog -Force -ErrorAction SilentlyContinue
        $r = Invoke-BrowserHost $hExe (StubArgs (Join-Path $hTmp 'd9') 'ok') (PathFrame $odd)
        $logged = if (Test-Path $stubLog) { [IO.File]::ReadAllText($stubLog, [Text.Encoding]::UTF8) } else { '' }
        Check 'kopru: ozel karakterli dosya adi tek harfi harfine arguman' ($r.reply -and $r.reply.level -eq 'OK' -and $logged -ceq $odd) ("log=$logged " + (HostWhy $r))

        # Varsayilan lastseen klasoru: kopru exe'sinin yanindaki data\
        $r = Invoke-BrowserHost $hExe @() (PathFrame (Join-Path $hTmp 'yok.exe'))
        Check 'kopru: varsayilan lastseen <exe klasoru>\data' ((Test-HostError $r $tMiss) -and (Test-Path (Join-Path $hTmp 'data\browser-lastseen.txt'))) (HostWhy $r)

        # Sembolik bag reddedilir (ayricalik yoksa atlanir)
        $lnkTarget = Join-Path $hTmp 'hedef.exe'
        [IO.File]::WriteAllBytes($lnkTarget, [byte[]](77, 90))
        $lnk = Join-Path $hTmp 'baglanti.exe'
        $prevEap = $ErrorActionPreference; $ErrorActionPreference = 'Continue'
        try { $mk = & cmd.exe /c mklink "$lnk" "$lnkTarget" 2>&1 | ForEach-Object { "$_" } | Out-String } catch { $mk = "$_" } finally { $ErrorActionPreference = $prevEap }
        if ((Test-Path -LiteralPath $lnk) -and ((Get-Item -LiteralPath $lnk -Force).Attributes -band [IO.FileAttributes]::ReparsePoint)) {
            $r = Invoke-BrowserHost $hExe (StubArgs (Join-Path $hTmp 'd11') 'ok') (PathFrame $lnk)
            Check 'kopru: sembolik bag -> ERROR' (Test-HostError $r 'Bu dosya taranamıyor') (HostWhy $r)
        } else { Write-Host "SKIP kopru: sembolik bag testi (mklink: $($mk.Trim()))" }

        # Zaman asimi: tarama ve onun alt sureci (is nesnesi) kapanir, yanit gecikmez
        $pidFile = "$stubLog.pid"
        Remove-Item $pidFile -Force -ErrorAction SilentlyContinue
        $tsw = [Diagnostics.Stopwatch]::StartNew()
        $r = Invoke-BrowserHost $hExe (StubArgs (Join-Path $hTmp 'd10') 'hang' @('--timeout-ms', '5000')) (PathFrame $vf) -TimeoutMs 40000
        $tSec = $tsw.Elapsed.TotalSeconds
        Check 'kopru: zaman asimi -> ERROR' ((Test-HostError $r 'Tarama zaman aşımına uğradı') -and $tSec -lt 25) ("sure=$tSec " + (HostWhy $r))
        $childPid = 0
        if (Test-Path $pidFile) { $childPid = [int]([IO.File]::ReadAllText($pidFile).Trim()) }
        $alive = $true
        for ($k = 0; $k -lt 20; $k++) {
            $cp = if ($childPid) { Get-Process -Id $childPid -ErrorAction SilentlyContinue } else { $null }
            if (-not $cp -or $cp.ProcessName -ne 'PING') { $alive = $false; break }
            Start-Sleep -Milliseconds 250
        }
        Check 'kopru: zaman asiminda taramanin alt sureci de kapanir' ($childPid -gt 0 -and -not $alive) "pid=$childPid"
        if ($alive -and $childPid) { Stop-Process -Id $childPid -Force -ErrorAction SilentlyContinue }
    }

    # CortmedSecurity.ps1 -Mode ScanFile -Json: gecici bir kopyada, bos bir CMDB ile, gecici bir .txt uzerinde
    $sw = Join-Path $hTmp 'scanwork'
    New-Item -ItemType Directory -Force $sw | Out-Null
    foreach ($f in 'CortmedSecurity.ps1', 'CortmedEngine.cs') { Copy-Item (Join-Path $root "windows\$f") $sw }
    $cmdb = New-Object IO.MemoryStream
    $bw = New-Object IO.BinaryWriter $cmdb
    $bw.Write([Text.Encoding]::ASCII.GetBytes('CMDB')); $bw.Write([uint16]1); $bw.Write([uint16]0); $bw.Write([long]1)
    $bw.Write([int]0); $bw.Write([int]0); $bw.Write([int]0); $bw.Flush()
    [IO.File]::WriteAllBytes((Join-Path $sw 'windows.cmdb'), $cmdb.ToArray())
    $txt = Join-Path $hTmp 'ornek belge.txt'
    [IO.File]::WriteAllText($txt, 'merhaba')
    $prevEnc = [Console]::OutputEncoding
    [Console]::OutputEncoding = New-Object System.Text.UTF8Encoding($false)
    $jOut = @(& $psExe -NoProfile -ExecutionPolicy Bypass -File (Join-Path $sw 'CortmedSecurity.ps1') -Mode ScanFile -Json -Path $txt 2>$null | ForEach-Object { "$_" })
    $jCode = $LASTEXITCODE
    [Console]::OutputEncoding = $prevEnc
    $jLines = @($jOut | Where-Object { $_.Trim() })
    $jObj = $null
    if ($jLines.Count -eq 1) { try { $jObj = $jLines[0] | ConvertFrom-Json } catch { } }
    Check 'ScanFile -Json tek gecerli JSON satiri, level RED/YELLOW/OK' ($jCode -eq 0 -and $jObj -and @('RED', 'YELLOW', 'OK') -ccontains $jObj.level -and [string]$jObj.title -and @($jObj.reasons).Count -le 5) ("kod $jCode, cikti: " + ($jOut -join ' / '))
} finally {
    Remove-Item -LiteralPath $hTmp -Recurse -Force -ErrorAction SilentlyContinue
    Remove-Item -LiteralPath $hFileDir -Recurse -Force -ErrorAction SilentlyContinue
}

# --- Eklenti ozel anahtari depoya girmemeli ---
$pemTracked = @(& git -C $root ls-files -- '*.pem' 'android/keystore' 2>$null)
Check 'eklenti ozel anahtari depoda izlenmiyor' ($pemTracked.Count -eq 0) ($pemTracked -join ', ')
$pemIgnored = & git -C $root check-ignore -q -- 'android/keystore/cortmed-extension.pem' 2>$null; $pemIgnoredOk = ($LASTEXITCODE -eq 0)
Check 'eklenti ozel anahtari .gitignore kapsaminda' $pemIgnoredOk ''

if ($fails -gt 0) { Write-Host "FAIL: $fails ek kontrol basarisiz"; exit 1 }
exit $exeCode
