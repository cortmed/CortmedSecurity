#Requires -Version 5.1
<#
  Cortmed Security - davranis bekcisi kurulumu (yonetici yetkisi ister, bir kez)
    * C:\Program Files\Cortmed ve C:\ProgramData\Cortmed: korumali ACL (kullanicilar yalnizca okur).
      Onceden var olan ama guvenilir durumda olmayan klasor (or. bir kullanicinin actigi) silinip yeniden olusturulur.
    * Bekci kaynaklarini Program Files'a kopyalar ve CortmedGuard.exe'yi ORADA derler
    * Davranis kurallarini ve Sysmon ayarini ProgramData'ya kopyalar
    * Sysmon yoksa Microsoft'un resmi zip'ini indirir, imzasini dogrular ve kurar
    * CortmedGuard hizmetini kurar (otomatik baslar, cokerse yeniden baslar) ve baslatir
  -WhatIf: yonetici gerektirmez, hicbir sey degistirmez; yapilacaklari yazar.
  Cikis kodu: 0 tamam, 2 hizmet kuruldu ama Sysmon kurulamadi, 1 hata.
  Yollar ortam degiskenlerinden degil, [Environment]'tan alinir (yukseltilmis islemde kullanici ortami guvenilmez).
#>
param(
    [string]$Source,
    [switch]$WhatIf,
    # Yalnizca test icin, -WhatIf ile gecerli: Sysmon algilamasini ve veri klasorunu sabitler
    [ValidateSet('Auto', 'Present', 'Absent')][string]$SysmonState = 'Auto',
    [string]$DataDir,
    # Kendini yonetici olarak yeniden baslattiginda verilir (pencere hatada acik kalir)
    [switch]$Elevated
)
$ErrorActionPreference = 'Stop'
if (-not $Source) { $Source = Split-Path -Parent $MyInvocation.MyCommand.Path }
$Source = (Resolve-Path $Source).Path.TrimEnd('\')

$winDir = [Environment]::GetFolderPath('Windows')
$sysDir = [Environment]::SystemDirectory
$app = Join-Path ([Environment]::GetFolderPath('ProgramFiles')) 'Cortmed'
$data = Join-Path ([Environment]::GetFolderPath('CommonApplicationData')) 'Cortmed'
if ($WhatIf -and $DataDir) { $data = $DataDir }
$exe = Join-Path $app 'CortmedGuard.exe'
$svcName = 'CortmedGuard'
$sc = Join-Path $sysDir 'sc.exe'
$sysmonUrl = 'https://download.sysinternals.com/files/Sysmon.zip'
$markOurs = Join-Path $data 'sysmon-installed-by-cortmed'
$markPre = Join-Path $data 'sysmon-preexisting'

# --- Guvenilir klasor denetimi. AYNI fonksiyon Uninstall-Guard.ps1'de de var (ayri dosya yerine kopya;
#     test ikisinin ayni oldugunu denetler). Degistirirseniz ikisini birlikte degistirin. ---
# Guvenilir: var, baglanti (reparse point) degil, sahibi Administrators veya SYSTEM, DACL korumali
# ve SYSTEM/Administrators disinda hicbir SID'e yazma izni yok.
function Test-TrustedDir([string]$dir) {
    try {
        $di = New-Object IO.DirectoryInfo $dir
        if (-not $di.Exists) { return $false }
        if ($di.Attributes -band [IO.FileAttributes]::ReparsePoint) { return $false }
        $acl = $di.GetAccessControl()
        $okSids = @('S-1-5-18', 'S-1-5-32-544')
        if ($okSids -notcontains $acl.GetOwner([Security.Principal.SecurityIdentifier]).Value) { return $false }
        if (-not $acl.AreAccessRulesProtected) { return $false }
        # Yazma sayilan haklar: veri/ek yazma, oznitelik, silme, izin ve sahiplik degistirme, genel yazma/tum
        $write = [int64]([Security.AccessControl.FileSystemRights]'WriteData, AppendData, WriteExtendedAttributes, WriteAttributes, Delete, DeleteSubdirectoriesAndFiles, ChangePermissions, TakeOwnership') -bor 0x50000000
        foreach ($r in $acl.GetAccessRules($true, $true, [Security.Principal.SecurityIdentifier])) {
            if ($r.AccessControlType -ne [Security.AccessControl.AccessControlType]::Allow) { continue }
            if ($okSids -contains $r.IdentityReference.Value) { continue }
            if (([int64]$r.FileSystemRights -band $write) -ne 0) { return $false }
        }
        return $true
    } catch { return $false }
}

# Baglantilari izlemeden siler: junction/symlink girdisinin kendisi silinir, hedefe hic girilmez.
# Dosyalar (hardlink dahil) yeniden izinlendirilmez, yalnizca silinir (hardlink'te yalnizca bag kopar).
function Remove-TreeSafe([string]$path) {
    $di = New-Object IO.DirectoryInfo $path
    if ($di.Exists) { Remove-EntrySafe $di }
    elseif ((New-Object IO.FileInfo $path).Exists) { [IO.File]::Delete($path) }
}
# $e: listelemeden gelen girdi; oznitelikleri baglantinin kendisine aittir (hedefe bakilmaz)
function Remove-EntrySafe([IO.FileSystemInfo]$e) {
    if ($e -is [IO.DirectoryInfo]) {
        if (-not ($e.Attributes -band [IO.FileAttributes]::ReparsePoint)) {
            foreach ($c in $e.GetFileSystemInfos()) { Remove-EntrySafe $c }
        }
        [IO.Directory]::Delete($e.FullName, $false)
    } else {
        [IO.File]::Delete($e.FullName)
    }
}
# --- /kopya ---

function First([string[]]$paths) { $paths | Where-Object { Test-Path $_ } | Select-Object -First 1 }
$guardDir = Join-Path $Source 'guard'
$engineCs = Join-Path $Source 'CortmedEngine.cs'
$sysmonXml = Join-Path $guardDir 'sysmon-cortmed.xml'
$uninstaller = Join-Path $Source 'Uninstall-Guard.ps1'
# Kaynaklar: pakette yan yana, gelistirme agacinda depo yollari
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
if (-not (Test-Path $uninstaller)) { $missing += 'Uninstall-Guard.ps1' }
if ($missing) { throw "Davranış bekçisi dosyaları bulunamadı: $($missing -join ', ')" }

# Klasorlerin bu calismanin BASINDAKI durumu. Isaretlere yalnizca veri klasoru guvenilirse inanilir;
# degilse klasor silinip yeniden olusturulur ve isaretler de gider.
$appTrusted = Test-TrustedDir $app
$dataTrusted = Test-TrustedDir $data
$oursMarked = $dataTrusted -and (Test-Path -LiteralPath $markOurs)
if ($WhatIf -and $SysmonState -ne 'Auto') {
    $sysmonPresent = ($SysmonState -eq 'Present')
} else {
    $sysmonSvc = Get-Service Sysmon64, Sysmon -ErrorAction SilentlyContinue | Select-Object -First 1
    $sysmonPresent = [bool]$sysmonSvc
}
$sysmonOurs = $sysmonPresent -and $oursMarked
$guardExists = [bool](Get-Service $svcName -ErrorAction SilentlyContinue)

function DirStep([string]$dir, [bool]$trusted) {
    if ($trusted) { "$dir korunuyor (zaten yalnızca yöneticiler yazabiliyor)" }
    elseif (Test-Path -LiteralPath $dir) { "$dir güvenilir durumda değil: içeriği silinip yalnızca yöneticilerin yazabileceği şekilde yeniden oluşturulacak" }
    else { "$dir oluşturulacak; yalnızca yöneticiler ve sistem yazabilecek, kullanıcılar yalnızca okuyabilecek" }
}
$sysmonStep = if (-not $sysmonPresent) { "Sysmon kurulacak (Microsoft'un resmi Sysmon.zip dosyası indirilip imzası doğrulanacak)" }
elseif ($sysmonOurs) { 'Sysmon daha önce Cortmed tarafından kurulmuş; yalnızca ayarı güncellenecek' }
else { 'Sysmon önceden kurulu, dokunulmayacak' }
$plan = @(
    (DirStep $app $appTrusted),
    (DirStep $data $dataTrusted),
    "Bekçi kaynakları $app\src klasörüne kopyalanıp orada CortmedGuard.exe olarak derlenecek",
    "Kaldırma betiği $app\Uninstall-Guard.ps1 olarak kopyalanacak",
    "Davranış kuralları ve Sysmon ayarı $data klasörüne kopyalanacak",
    $sysmonStep,
    $(if ($guardExists) { 'CortmedGuard hizmeti durdurulup güncellenecek ve yeniden başlatılacak' }
        else { 'CortmedGuard hizmeti kurulacak (her açılışta başlar, çökerse yeniden başlar) ve başlatılacak' }))

if ($WhatIf) {
    Write-Host '  Davranış bekçisi kurulum planı (-WhatIf: hiçbir şey değiştirilmedi):'
    foreach ($s in $plan) { Write-Host "   - $s" }
    exit 0
}

# Yonetici degilse ya da 64 bit Windows'ta 32 bit PowerShell ise (Program Files x86 olur) 64 bit PowerShell'i
# yonetici olarak yeniden baslat, profil yuklenmeden. UAC reddedilirse Start-Process istisna firlatir (cagirana gider).
$me = [Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()
$isAdmin = $me.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
$wow = [Environment]::Is64BitOperatingSystem -and -not [Environment]::Is64BitProcess
if (-not $isAdmin -or $wow) {
    $psDir = if ($wow) { Join-Path $winDir 'Sysnative' } else { $sysDir }
    $ps = Join-Path $psDir 'WindowsPowerShell\v1.0\powershell.exe'
    $argLine = '-NoProfile -ExecutionPolicy Bypass -File "{0}" -Source "{1}" -Elevated' -f $PSCommandPath, $Source
    $p = Start-Process $ps -Verb RunAs -ArgumentList $argLine -Wait -PassThru -ErrorAction Stop
    exit $p.ExitCode
}

$admins = New-Object Security.Principal.SecurityIdentifier([Security.Principal.WellKnownSidType]::BuiltinAdministratorsSid, $null)

# Korumali ACL: SYSTEM ve Administrators tam yetki, Users okuma/calistirma; iyi bilinen SID'ler
function New-ProtectedAcl {
    $ds = New-Object Security.AccessControl.DirectorySecurity
    $ds.SetAccessRuleProtection($true, $false)
    $ds.SetOwner($admins)
    $inherit = [Security.AccessControl.InheritanceFlags]'ContainerInherit, ObjectInherit'
    foreach ($r in @(@('LocalSystemSid', 'FullControl'), @('BuiltinAdministratorsSid', 'FullControl'), @('BuiltinUsersSid', 'ReadAndExecute'))) {
        $sid = New-Object Security.Principal.SecurityIdentifier([Security.Principal.WellKnownSidType]$r[0], $null)
        $ds.AddAccessRule((New-Object Security.AccessControl.FileSystemAccessRule($sid, [Security.AccessControl.FileSystemRights]$r[1],
                    $inherit, [Security.AccessControl.PropagationFlags]::None, [Security.AccessControl.AccessControlType]::Allow)))
    }
    $ds
}

# Guvenilir klasor (yukseltme) oldugu gibi kalir. Degilse: baglantilari izlemeden silinir, sonra ACL'si
# olusturma aninda verilerek (arada acik pencere yok) yeniden yaratilir ve dogrulanir.
function Initialize-SecureDir([string]$dir, [bool]$trusted) {
    if ($trusted -and (Test-TrustedDir $dir)) { return }
    for ($i = 0; $i -lt 3; $i++) {
        Remove-TreeSafe $dir
        $made = [IO.Directory]::CreateDirectory($dir, (New-ProtectedAcl))
        # Arada baskasi ayni adi aldiysa (baglanti ya da kendi klasoru) dogrulama tutmaz: tekrar sil
        if ((Test-TrustedDir $dir) -and @($made.GetFileSystemInfos()).Count -eq 0) { return }
    }
    throw "$dir güvenli olarak oluşturulamadı."
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
    Set-Location $winDir
    # Modulleri PSModulePath yerine Windows PowerShell'in kendi klasorunden yukle
    Import-Module (Join-Path $PSHOME 'Modules\Microsoft.PowerShell.Archive')
    Import-Module (Join-Path $PSHOME 'Modules\Microsoft.PowerShell.Security')

    # 1) Klasorler ve ACL (hizmet baslamadan once)
    Initialize-SecureDir $app $appTrusted
    Initialize-SecureDir $data $dataTrusted
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
    Remove-TreeSafe $srcDir
    New-Item -ItemType Directory $srcDir | Out-Null
    foreach ($f in $csFiles + $engineCs) { Copy-Item $f $srcDir -Force }
    $csc = Join-Path $winDir 'Microsoft.NET\Framework64\v4.0.30319\csc.exe'
    if (-not (Test-Path $csc)) { $csc = Join-Path $winDir 'Microsoft.NET\Framework\v4.0.30319\csc.exe' }
    $newExe = Join-Path $app 'CortmedGuard.new.exe'
    $refs = 'System.dll', 'System.Core.dll', 'System.Xml.dll', 'System.Xml.Linq.dll', 'System.ServiceProcess.dll', 'System.Web.Extensions.dll'
    $cscArgs = @('/nologo', '/target:exe', '/platform:anycpu', '/optimize+', '/codepage:65001', "/out:$newExe") +
        ($refs | ForEach-Object { "/reference:$_" }) + @(Get-ChildItem $srcDir -Filter *.cs | ForEach-Object FullName)
    $out = & $csc @cscArgs
    if ($LASTEXITCODE -ne 0 -or -not (Test-Path $newExe)) { throw "CortmedGuard derlenemedi: $($out -join ' ')" }
    Write-Host '  [OK] CortmedGuard.exe derlendi' -ForegroundColor Green
    # Kaldirma betigi: Uninstall.ps1 yalnizca bu (kullanicinin yazamadigi) kopyayi yukseltir
    Copy-Item $uninstaller $app -Force

    # 4) Sysmon: var + guvenilir isaret -> bizim, ayari tazele; var + isaret yok -> onceden kurulu; yok -> kur
    if ($sysmonPresent -and -not $sysmonOurs) {
        Set-Content $markPre 'cortmed' -Encoding ASCII
        Write-Host '  Sysmon önceden kurulu, dokunulmayacak'
    } elseif ($sysmonOurs) {
        $sm = Join-Path $winDir "$($sysmonSvc.Name).exe"
        if (-not (Test-Path $sm)) { $warn += "Sysmon ayarı güncellenemedi: $sm yok." }
        else {
            & $sm -c $dataXml | Out-Null
            if ($LASTEXITCODE -ne 0) { $warn += "Sysmon ayarı güncellenemedi (kod $LASTEXITCODE)." }
            else { Write-Host '  [OK] Sysmon ayarı güncellendi' -ForegroundColor Green }
        }
    } else {
        $tmp = Join-Path $app 'sysmon-tmp'
        try {
            Remove-TreeSafe $tmp
            New-Item -ItemType Directory $tmp | Out-Null
            Write-Host '  Sysmon indiriliyor (Microsoft Sysinternals)...'
            [Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12
            $zip = Join-Path $tmp 'Sysmon.zip'
            Invoke-WebRequest $sysmonUrl -OutFile $zip -UseBasicParsing
            Expand-Archive $zip $tmp -Force
            $s64 = Join-Path $tmp 'Sysmon64.exe'
            if (-not (Test-Path $s64)) { throw 'İndirilen pakette Sysmon64.exe yok; Sysmon kurulmadı.' }
            $sig = Get-AuthenticodeSignature $s64
            $signer = if ($sig.SignerCertificate) { $sig.SignerCertificate.GetNameInfo([Security.Cryptography.X509Certificates.X509NameType]::SimpleName, $false) }
            if ($sig.Status -ne [Management.Automation.SignatureStatus]::Valid -or $signer -ne 'Microsoft Corporation') {
                throw "Sysmon64.exe'nin Microsoft imzası doğrulanamadı; güvenlik için Sysmon kurulmadı."
            }
            & $s64 -accepteula -i $dataXml | Out-Null
            if ($LASTEXITCODE -ne 0) { throw "Sysmon kurulamadı (kod $LASTEXITCODE)." }
            Set-Content $markOurs 'cortmed' -Encoding ASCII
            Remove-Item -LiteralPath $markPre -Force -ErrorAction SilentlyContinue
            Write-Host '  [OK] Sysmon kuruldu' -ForegroundColor Green
        } catch {
            $warn += "Sysmon kurulmadı: $($_.Exception.Message)"
        } finally {
            Set-Location $winDir
            try { Remove-TreeSafe $tmp } catch { }
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
    try { Move-Item $newExe $exe -Force }
    catch {
        # Yukseltme yarida kaldi: eski hizmeti yeniden baslat ki bekci kapali kalmasin
        if ($existing) { Invoke-Sc "start $svcName" -AllowFail }
        throw "CortmedGuard.exe değiştirilemedi (eski sürüm çalışmaya devam ediyor): $($_.Exception.Message)"
    }
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
