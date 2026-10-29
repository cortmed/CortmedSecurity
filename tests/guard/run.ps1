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
    $bad = @($xml.SelectNodes('//RuleGroup/*') | Where-Object { $_.GetAttribute('onmatch') -ne 'include' })
    Check 'sysmon tum kurallar include' ($bad.Count -eq 0) ''
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

if ($fails -gt 0) { Write-Host "FAIL: $fails ek kontrol basarisiz"; exit 1 }
exit $exeCode
