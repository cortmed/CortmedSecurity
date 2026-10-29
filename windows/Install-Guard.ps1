#Requires -Version 5.1
<#
  Cortmed Security - davranis bekcisi kurulumu (yonetici yetkisi ister, bir kez)
    * C:\Program Files\Cortmed ve C:\ProgramData\Cortmed: korumali ACL (kullanicilar yalnizca okur)
    * Bekci kaynaklarini Program Files'a kopyalar ve CortmedGuard.exe'yi ORADA derler
    * Davranis kurallarini ve Sysmon ayarini ProgramData'ya kopyalar
    * Sysmon yoksa Microsoft'un resmi zip'ini indirir, imzasini dogrular ve kurar
    * CortmedGuard hizmetini kurar (otomatik baslar, cokerse yeniden baslar) ve baslatir
  -WhatIf: yonetici gerektirmez, hicbir sey degistirmez; yapilacaklari yazar.
  Cikis kodu: 0 tamam, 2 hizmet kuruldu ama Sysmon kurulamadi, 1 hata.
#>
param(
    [string]$Source,
    [switch]$WhatIf,
    # Yalnizca test icin, -WhatIf ile gecerli: Sysmon algilamasini sabitler
    [ValidateSet('Auto', 'Present', 'Absent')][string]$SysmonState = 'Auto',
    # Kendini yonetici olarak yeniden baslattiginda verilir (pencere hatada acik kalir)
    [switch]$Elevated
)
$ErrorActionPreference = 'Stop'
if (-not $Source) { $Source = Split-Path -Parent $MyInvocation.MyCommand.Path }
$Source = (Resolve-Path $Source).Path.TrimEnd('\')

$pfBase = if ($env:ProgramW6432) { $env:ProgramW6432 } else { $env:ProgramFiles }
$app = Join-Path $pfBase 'Cortmed'
$data = Join-Path $env:ProgramData 'Cortmed'
$exe = Join-Path $app 'CortmedGuard.exe'
$svcName = 'CortmedGuard'
$sc = Join-Path $env:windir 'System32\sc.exe'
$icacls = Join-Path $env:windir 'System32\icacls.exe'
$sysmonUrl = 'https://download.sysinternals.com/files/Sysmon.zip'
$markOurs = Join-Path $data 'sysmon-installed-by-cortmed'
$markPre = Join-Path $data 'sysmon-preexisting'

# Kaynaklar: pakette yan yana, gelistirme agacinda depo yollari
function First([string[]]$paths) { $paths | Where-Object { Test-Path $_ } | Select-Object -First 1 }
$guardDir = Join-Path $Source 'guard'
$engineCs = Join-Path $Source 'CortmedEngine.cs'
$sysmonXml = Join-Path $guardDir 'sysmon-cortmed.xml'
$rules = First @((Join-Path $Source 'behavior_rules.json'), (Join-Path $Source '..\engine\rules\behavior_rules.json'))
$sigDir = @($Source, (Join-Path $Source '..\engine\dist')) |
    Where-Object { (Test-Path (Join-Path $_ 'manifest.json')) -and (Test-Path (Join-Path $_ 'manifest.sig')) } | Select-Object -First 1
$csFiles = @(foreach ($d in 'Core', 'Service') {
        $p = Join-Path $guardDir $d
        if (Test-Path $p) { Get-ChildItem $p -Filter *.cs | ForEach-Object FullName }
    })
$missing = @()
if ($csFiles.Count -eq 0) { $missing += 'guard\Core, guard\Service' }
if (-not (Test-Path $engineCs)) { $missing += 'CortmedEngine.cs' }
if (-not (Test-Path $sysmonXml)) { $missing += 'guard\sysmon-cortmed.xml' }
if (-not $rules) { $missing += 'behavior_rules.json' }
if ($missing) { throw "Davranış bekçisi dosyaları bulunamadı: $($missing -join ', ')" }

# Sysmon durumu: hizmeti varsa kurulu. Bizim isaretimiz varsa onu biz kurmusuzdur.
if ($WhatIf -and $SysmonState -ne 'Auto') {
    $sysmonPresent = ($SysmonState -eq 'Present'); $sysmonOurs = $false
} else {
    $sysmonSvc = Get-Service Sysmon64, Sysmon -ErrorAction SilentlyContinue | Select-Object -First 1
    $sysmonPresent = [bool]$sysmonSvc
    $sysmonOurs = $sysmonPresent -and (Test-Path $markOurs)
}
$guardExists = [bool](Get-Service $svcName -ErrorAction SilentlyContinue)

$sysmonStep = if (-not $sysmonPresent) { "Sysmon kurulacak (Microsoft'un resmi Sysmon.zip dosyası indirilip imzası doğrulanacak)" }
elseif ($sysmonOurs) { 'Sysmon daha önce Cortmed tarafından kurulmuş; yalnızca ayarı güncellenecek' }
else { 'Sysmon önceden kurulu, dokunulmayacak' }
$plan = @(
    "$app ve $data oluşturulacak; yalnızca yöneticiler ve sistem yazabilecek, kullanıcılar yalnızca okuyabilecek",
    "Bekçi kaynakları $app\src klasörüne kopyalanıp orada CortmedGuard.exe olarak derlenecek",
    "Davranış kuralları ve Sysmon ayarı $data klasörüne kopyalanacak",
    $sysmonStep,
    $(if ($guardExists) { 'CortmedGuard hizmeti durdurulup güncellenecek ve yeniden başlatılacak' }
        else { 'CortmedGuard hizmeti kurulacak (her açılışta başlar, çökerse yeniden başlar) ve başlatılacak' }))

if ($WhatIf) {
    Write-Host '  Davranış bekçisi kurulum planı (-WhatIf: hiçbir şey değiştirilmedi):'
    foreach ($s in $plan) { Write-Host "   - $s" }
    exit 0
}

# Yonetici degilse kendini UAC ile yeniden baslat. UAC reddedilirse Start-Process istisna firlatir (cagirana gider).
$me = [Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()
if (-not $me.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    $argLine = '-NoProfile -ExecutionPolicy Bypass -File "{0}" -Source "{1}" -Elevated' -f $PSCommandPath, $Source
    $p = Start-Process powershell.exe -Verb RunAs -ArgumentList $argLine -Wait -PassThru -ErrorAction Stop
    exit $p.ExitCode
}

$admins = New-Object Security.Principal.SecurityIdentifier([Security.Principal.WellKnownSidType]::BuiltinAdministratorsSid, $null)

# Korumali ACL: SYSTEM ve Administrators tam yetki, Users okuma/calistirma; iyi bilinen SID'ler
function Set-ProtectedAcl([string]$dir) {
    $ds = New-Object Security.AccessControl.DirectorySecurity
    $ds.SetAccessRuleProtection($true, $false)
    $ds.SetOwner($admins)
    $inherit = [Security.AccessControl.InheritanceFlags]'ContainerInherit, ObjectInherit'
    foreach ($r in @(@('LocalSystemSid', 'FullControl'), @('BuiltinAdministratorsSid', 'FullControl'), @('BuiltinUsersSid', 'ReadAndExecute'))) {
        $sid = New-Object Security.Principal.SecurityIdentifier([Security.Principal.WellKnownSidType]$r[0], $null)
        $ds.AddAccessRule((New-Object Security.AccessControl.FileSystemAccessRule($sid, [Security.AccessControl.FileSystemRights]$r[1],
                    $inherit, [Security.AccessControl.PropagationFlags]::None, [Security.AccessControl.AccessControlType]::Allow)))
    }
    [IO.Directory]::SetAccessControl($dir, $ds)
}

# Onceden var olan alt ogeler: sahip Administrators, acik izinler silinir, yalnizca miras kalir.
# Yukaridan asagi: once klasor kilitlenir, sonra icine bakilir. Baglantilar (junction/symlink) hedefe
# dokunmadan silinir; boylece yetkili islem kullanicinin gosterdigi baska bir yere uzanmaz.
function Reset-Children([string]$dir) {
    foreach ($e in (New-Object IO.DirectoryInfo $dir).GetFileSystemInfos()) {
        $isDir = $e -is [IO.DirectoryInfo]
        if ($e.Attributes -band [IO.FileAttributes]::ReparsePoint) {
            if ($isDir) { [IO.Directory]::Delete($e.FullName) } else { [IO.File]::Delete($e.FullName) }
            continue
        }
        $s = if ($isDir) { New-Object Security.AccessControl.DirectorySecurity } else { New-Object Security.AccessControl.FileSecurity }
        $s.SetAccessRuleProtection($false, $false)
        try {
            $so = if ($isDir) { New-Object Security.AccessControl.DirectorySecurity } else { New-Object Security.AccessControl.FileSecurity }
            $so.SetOwner($admins)
            $e.SetAccessControl($so)
        } catch {
            # Kullanici yoneticileri disarida birakmissa sahipligi ayricalikla (icacls) al
            & $icacls $e.FullName /setowner '*S-1-5-32-544' /L /C /Q | Out-Null
        }
        $e.SetAccessControl($s)
        if ($isDir) { Reset-Children $e.FullName }
    }
}

function Initialize-SecureDir([string]$dir) {
    $it = Get-Item -LiteralPath $dir -Force -ErrorAction SilentlyContinue
    if ($it -and ($it.Attributes -band [IO.FileAttributes]::ReparsePoint)) { [IO.Directory]::Delete($dir) }
    New-Item -ItemType Directory -Force $dir | Out-Null
    Set-ProtectedAcl $dir
    Reset-Children $dir
}

function Invoke-Sc([string]$argLine, [switch]$AllowFail) {
    $psi = New-Object Diagnostics.ProcessStartInfo($sc, $argLine)
    $psi.UseShellExecute = $false; $psi.CreateNoWindow = $true
    $psi.RedirectStandardOutput = $true; $psi.RedirectStandardError = $true
    $p = [Diagnostics.Process]::Start($psi)
    $o = $p.StandardOutput.ReadToEnd() + $p.StandardError.ReadToEnd()
    $p.WaitForExit()
    if ($p.ExitCode -ne 0 -and -not $AllowFail) { throw "sc.exe $argLine başarısız (kod $($p.ExitCode)): $($o.Trim())" }
}

$warn = @()
try {
    Write-Host ''
    Write-Host '  CORTMED davranış bekçisi kuruluyor...' -ForegroundColor Cyan
    Set-Location $env:windir

    # 1) Klasorler ve ACL (hizmet baslamadan once)
    Initialize-SecureDir $app
    Initialize-SecureDir $data
    Write-Host '  [OK] Klasörler hazır (kullanıcılar yalnızca okuyabilir)' -ForegroundColor Green

    # 2) Kurallar, imza ve Sysmon ayari
    Copy-Item $rules (Join-Path $data 'behavior-rules.json') -Force
    Copy-Item $rules (Join-Path $data 'behavior-rules.json.good') -Force
    if ($sigDir) {
        Copy-Item (Join-Path $sigDir 'manifest.json') $data -Force
        Copy-Item (Join-Path $sigDir 'manifest.sig') $data -Force
    }
    $dataXml = Join-Path $data 'sysmon-cortmed.xml'
    Copy-Item $sysmonXml $dataXml -Force

    # 3) Kaynaklari Program Files'a kopyala ve orada derle (once yeni ad; hizmet ancak derleme tutarsa durur)
    $srcDir = Join-Path $app 'src'
    if (Test-Path $srcDir) { Remove-Item $srcDir -Recurse -Force }
    New-Item -ItemType Directory -Force $srcDir | Out-Null
    foreach ($f in $csFiles + $engineCs) { Copy-Item $f $srcDir -Force }
    $csc = Join-Path $env:windir 'Microsoft.NET\Framework64\v4.0.30319\csc.exe'
    if (-not (Test-Path $csc)) { $csc = Join-Path $env:windir 'Microsoft.NET\Framework\v4.0.30319\csc.exe' }
    $newExe = Join-Path $app 'CortmedGuard.new.exe'
    $refs = 'System.dll', 'System.Core.dll', 'System.Xml.dll', 'System.Xml.Linq.dll', 'System.ServiceProcess.dll', 'System.Web.Extensions.dll'
    $cscArgs = @('/nologo', '/target:exe', '/platform:anycpu', '/optimize+', '/codepage:65001', "/out:$newExe") +
        ($refs | ForEach-Object { "/reference:$_" }) + @(Get-ChildItem $srcDir -Filter *.cs | ForEach-Object FullName)
    $out = & $csc @cscArgs
    if ($LASTEXITCODE -ne 0 -or -not (Test-Path $newExe)) { throw "CortmedGuard derlenemedi: $($out -join ' ')" }
    Write-Host '  [OK] CortmedGuard.exe derlendi' -ForegroundColor Green

    # 4) Sysmon
    if ($sysmonPresent -and -not $sysmonOurs) {
        Set-Content $markPre 'cortmed' -Encoding ASCII
        Write-Host '  Sysmon önceden kurulu, dokunulmayacak'
    } elseif ($sysmonOurs) {
        $sm = Join-Path $env:windir "$($sysmonSvc.Name).exe"
        if (-not (Test-Path $sm)) { $warn += "Sysmon ayarı güncellenemedi: $sm yok." }
        else {
            & $sm -c $dataXml | Out-Null
            if ($LASTEXITCODE -ne 0) { $warn += "Sysmon ayarı güncellenemedi (kod $LASTEXITCODE)." }
            else { Write-Host '  [OK] Sysmon ayarı güncellendi' -ForegroundColor Green }
        }
    } else {
        $tmp = Join-Path $app 'sysmon-tmp'
        try {
            if (Test-Path $tmp) { Remove-Item $tmp -Recurse -Force }
            New-Item -ItemType Directory -Force $tmp | Out-Null
            Write-Host '  Sysmon indiriliyor (Microsoft Sysinternals)...'
            [Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12
            $zip = Join-Path $tmp 'Sysmon.zip'
            Invoke-WebRequest $sysmonUrl -OutFile $zip -UseBasicParsing
            Expand-Archive $zip $tmp -Force
            $s64 = Join-Path $tmp 'Sysmon64.exe'
            if (-not (Test-Path $s64)) { throw 'İndirilen pakette Sysmon64.exe yok; Sysmon kurulmadı.' }
            $sig = Get-AuthenticodeSignature $s64
            if ($sig.Status -ne 'Valid' -or -not $sig.SignerCertificate -or $sig.SignerCertificate.Subject -notlike '*CN=Microsoft Corporation*') {
                throw "Sysmon64.exe'nin Microsoft imzası doğrulanamadı; güvenlik için Sysmon kurulmadı."
            }
            & $s64 -accepteula -i $dataXml | Out-Null
            if ($LASTEXITCODE -ne 0) { throw "Sysmon kurulamadı (kod $LASTEXITCODE)." }
            Set-Content $markOurs 'cortmed' -Encoding ASCII
            Remove-Item $markPre -Force -ErrorAction SilentlyContinue
            Write-Host '  [OK] Sysmon kuruldu' -ForegroundColor Green
        } catch {
            $warn += "Sysmon kurulmadı: $($_.Exception.Message)"
        } finally {
            Set-Location $env:windir
            Remove-Item $tmp -Recurse -Force -ErrorAction SilentlyContinue
        }
    }

    # 5) Hizmet: varsa durdur, exe'yi degistir, yeniden ayarla; yoksa kur
    $existing = Get-Service $svcName -ErrorAction SilentlyContinue
    if ($existing) {
        if ($existing.Status -ne 'Stopped') {
            Invoke-Sc "stop $svcName" -AllowFail
            try { $existing.WaitForStatus('Stopped', [TimeSpan]::FromSeconds(30)) } catch { }
        }
        Get-Process CortmedGuard -ErrorAction SilentlyContinue | Stop-Process -Force -ErrorAction SilentlyContinue
        Start-Sleep -Milliseconds 500
    }
    Move-Item $newExe $exe -Force
    $bin = 'binPath= "\"' + $exe + '\""'
    if ($existing) { Invoke-Sc "config $svcName $bin start= auto obj= LocalSystem" }
    else { Invoke-Sc "create $svcName $bin start= auto obj= LocalSystem" }
    Invoke-Sc "failure $svcName reset= 86400 actions= restart/5000/restart/5000/restart/5000"
    Invoke-Sc "start $svcName"
    Write-Host '  [OK] CortmedGuard hizmeti çalışıyor' -ForegroundColor Green
} catch {
    Write-Host "  Davranış bekçisi kurulamadı: $($_.Exception.Message)" -ForegroundColor Red
    if ($Elevated) { Read-Host '  Kapatmak için Enter' | Out-Null }
    exit 1
}

if ($warn) {
    foreach ($w in $warn) { Write-Host "  $w" -ForegroundColor Yellow }
    Write-Host '  Davranış bekçisi Sysmon olmadan olayları göremez; daha sonra kurulumu yeniden çalıştırabilirsiniz.' -ForegroundColor Yellow
    if ($Elevated) { Read-Host '  Kapatmak için Enter' | Out-Null }
    exit 2
}
exit 0
