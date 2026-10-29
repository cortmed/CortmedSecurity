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
    foreach ($m in '0x1010','0x1410','0x1438','0x143a','0x1fffff','0x1f1fff','0x1f3fff','0x40','0x10') {
        Check "sysmon GrantedAccess $m" ($gaList -contains $m) ($gaList -join ';')
    }
    Check 'sysmon GrantedAccess 0x1000 (yalniz sorgu) yok' ($gaList -notcontains '0x1000') ''
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
    }
} finally { Remove-Item $btTmp -Recurse -Force -ErrorAction SilentlyContinue }

if ($fails -gt 0) { Write-Host "FAIL: $fails ek kontrol basarisiz"; exit 1 }
exit $exeCode
