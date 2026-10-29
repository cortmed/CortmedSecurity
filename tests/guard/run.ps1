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
        $q = "//RuleGroup/$el[@onmatch='$mode']/$field"
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
    Check 'sysmon HashAlgorithms SHA256' ($xml.DocumentElement.SelectSingleNode('HashAlgorithms').InnerText -eq 'SHA256') ''
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

# Guvenilir klasor denetimi ve baglanti izlemeyen silme: iki betikteki kopyalar ayni, ve gecici klasorde davranis
$fnNames = 'Test-TrustedDir', 'Remove-TreeSafe', 'Remove-EntrySafe'
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
if ($fnNames | Where-Object { -not $igFns.ContainsKey($_) }) {
    Check 'guven/silme fonksiyonlari yuklendi' $false ''
} else {
    $tt = Join-Path ([IO.Path]::GetTempPath()) ('cortmed-trust-' + [Guid]::NewGuid().ToString('N'))
    New-Item -ItemType Directory -Force $tt | Out-Null
    try {
        $userDir = Join-Path $tt 'userdir'
        New-Item -ItemType Directory $userDir | Out-Null
        Check 'Test-TrustedDir: kullanicinin actigi klasor guvenilmez' (-not (Test-TrustedDir $userDir)) ''
        Check 'Test-TrustedDir: olmayan klasor guvenilmez' (-not (Test-TrustedDir (Join-Path $tt 'yok'))) ''
        $target = Join-Path $tt 'target'
        New-Item -ItemType Directory $target | Out-Null
        'keep' | Set-Content (Join-Path $target 'keep.txt')
        'hard' | Set-Content (Join-Path $target 'hard.txt')
        $jtop = Join-Path $tt 'jtop'
        cmd /c mklink /J "$jtop" "$target" | Out-Null
        Check 'Test-TrustedDir: junction guvenilmez' (-not (Test-TrustedDir $jtop)) ''
        $victim = Join-Path $tt 'victim'
        New-Item -ItemType Directory (Join-Path $victim 'sub') | Out-Null
        'a' | Set-Content (Join-Path $victim 'a.txt')
        'b' | Set-Content (Join-Path $victim 'sub\b.txt')
        cmd /c mklink /J "$(Join-Path $victim 'link')" "$target" | Out-Null
        cmd /c mklink /J "$(Join-Path $victim 'sub\link2')" "$target" | Out-Null
        cmd /c mklink /H "$(Join-Path $victim 'hl.txt')" "$(Join-Path $target 'hard.txt')" | Out-Null
        $planted = (Test-Path (Join-Path $victim 'link\keep.txt')) -and (Test-Path (Join-Path $victim 'hl.txt'))
        Check 'silme testi: junction ve hardlink kuruldu' $planted ''
        $err = ''
        try { Remove-TreeSafe $victim } catch { $err = $_.Exception.Message }
        Check 'Remove-TreeSafe klasoru siler' (-not (Test-Path $victim)) $err
        Check 'Remove-TreeSafe junction hedefine dokunmaz' ((Test-Path (Join-Path $target 'keep.txt')) -and (Test-Path $target)) ''
        Check 'Remove-TreeSafe hardlink hedefini silmez' ((Test-Path (Join-Path $target 'hard.txt')) -and ((Get-Content (Join-Path $target 'hard.txt')) -eq 'hard')) ''
        $err = ''
        try { Remove-TreeSafe $jtop } catch { $err = $_.Exception.Message }
        Check 'Remove-TreeSafe ust duzey junction: yalnizca bag silinir' ((-not (Test-Path $jtop)) -and (Test-Path (Join-Path $target 'keep.txt'))) $err

        # Guvenilmeyen veri klasorundeki isarete inanilmaz (-WhatIf, test veri klasoru)
        $fakeData = Join-Path $tt 'data'
        New-Item -ItemType Directory $fakeData | Out-Null
        'x' | Set-Content (Join-Path $fakeData 'sysmon-installed-by-cortmed')
        $o = ''
        if (Test-Path $ig) {
            $o = & powershell.exe -NoProfile -ExecutionPolicy Bypass -File $ig -Source (Join-Path $root 'windows') -WhatIf -SysmonState Present -DataDir $fakeData | Out-String
        }
        Check 'WhatIf: guvenilmeyen klasordeki isaret yok sayilir' ($o -match ('Sysmon ' + [char]0xF6 + 'nceden kurulu, dokunulmayacak') -and $o -notmatch 'Cortmed taraf') $o
        Check 'WhatIf: guvenilmeyen veri klasoru yeniden olusturulacak' ($o -match [regex]::Escape($fakeData) -and $o -match 'yeniden olu') $o
        Check 'WhatIf: isaret dosyasina dokunulmadi' (Test-Path (Join-Path $fakeData 'sysmon-installed-by-cortmed')) ''
    } finally {
        Get-ChildItem $tt -Force -ErrorAction SilentlyContinue | Where-Object { $_.Attributes -band [IO.FileAttributes]::ReparsePoint } |
            ForEach-Object { cmd /c rmdir "$($_.FullName)" }
        cmd /c rmdir /s /q "$tt"
    }
}

# Yukseltilmis betikler: ortam degiskeni yolu yok, Remove-Item -Recurse yok, imzalayan tam eslesme
foreach ($s in $ig, $ug) {
    $txt = if (Test-Path $s) { Get-Content $s -Raw -Encoding UTF8 } else { '$env:' }
    $leaf = Split-Path $s -Leaf
    Check "$leaf ortam degiskeninden yol almaz" ($txt -notmatch '\$env:') ''
    Check "$leaf Remove-Item -Recurse kullanmaz" ($txt -notmatch 'Remove-Item[^\r\n]*-Recurse') ''
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

if ($fails -gt 0) { Write-Host "FAIL: $fails ek kontrol basarisiz"; exit 1 }
exit $exeCode
