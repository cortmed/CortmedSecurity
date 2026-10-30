#Requires -Version 5.1
<#
  Cortmed Security - davranis bekcisi kurulumu (yonetici yetkisi ister, bir kez)
    * C:\Program Files\Cortmed ve C:\ProgramData\Cortmed: korumali ACL (kullanicilar yalnizca okur).
      Onceden var olan ama guvenilir durumda olmayan klasor (or. bir kullanicinin actigi) SILINMEZ:
      tek bir yeniden adlandirmayla "<ad>.untrusted-<zaman>" olarak kenara alinir, icine dokunulmaz.
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
$cmd = Join-Path $sysDir 'cmd.exe'
$sysmonUrl = 'https://download.sysinternals.com/files/Sysmon.zip'
$markOurs = Join-Path $data 'sysmon-installed-by-cortmed'
$markPre = Join-Path $data 'sysmon-preexisting'

# --- Klasor guveni. AYNI uc fonksiyon Uninstall-Guard.ps1'de de var (ayri dosya yerine kopya;
#     test ikisinin ayni oldugunu denetler). Degistirirseniz ikisini birlikte degistirin. ---
# Guvenilir: dizin, baglanti (reparse point) degil, sahibi SYSTEM veya Administrators, DACL korumali
# ve SYSTEM/Administrators disinda hicbir SID'e yazma izni yok. Hepsi TEK bir tutamactan okunur;
# Tutamac FILE_LIST_DIRECTORY (veri erisim hakki) ile ve FILE_SHARE_DELETE vermeden acilir; boylece paylasim
# denetimi uygulanir ve tutamac acik kaldikca klasor yeniden adlandirilamaz/silinemez (sabitlenir).
function Add-DirTrustType {
    if ('CortmedSetup.DirTrust' -as [type]) { return }
    Add-Type -TypeDefinition @'
using System;
using System.Runtime.InteropServices;
using System.Security.AccessControl;
using Microsoft.Win32.SafeHandles;

namespace CortmedSetup
{
    public static class DirTrust
    {
        const uint READ_CONTROL = 0x00020000, FILE_READ_ATTRIBUTES = 0x80, FILE_LIST_DIRECTORY = 0x1;
        const uint FILE_SHARE_READ = 1, FILE_SHARE_WRITE = 2, OPEN_EXISTING = 3;
        const uint FILE_FLAG_BACKUP_SEMANTICS = 0x02000000, FILE_FLAG_OPEN_REPARSE_POINT = 0x00200000;
        const uint ATTR_DIRECTORY = 0x10, ATTR_REPARSE = 0x400;
        const uint OWNER_SECURITY_INFORMATION = 1, DACL_SECURITY_INFORMATION = 4;
        const int SE_FILE_OBJECT = 1;
        // Yazma sayilan haklar: veri/ek yazma, EA, alt silme, oznitelik, silme, izin/sahip degistirme, genel yazma/tum, azami
        const int WriteMask = 0x2 | 0x4 | 0x10 | 0x40 | 0x100 | 0x10000 | 0x40000 | 0x80000 | 0x40000000 | 0x10000000 | 0x02000000;

        [StructLayout(LayoutKind.Sequential)]
        struct FileInfo
        {
            public uint Attributes;
            public uint C1, C2, A1, A2, W1, W2;
            public uint Volume, SizeHigh, SizeLow, Links, IndexHigh, IndexLow;
        }

        [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        static extern SafeFileHandle CreateFileW(string name, uint access, uint share, IntPtr sa, uint disposition, uint flags, IntPtr template);
        [DllImport("kernel32.dll", SetLastError = true)]
        static extern bool GetFileInformationByHandle(SafeFileHandle h, out FileInfo info);
        [DllImport("advapi32.dll")]
        static extern uint GetSecurityInfo(SafeFileHandle h, int type, uint info, out IntPtr owner, out IntPtr group, out IntPtr dacl, out IntPtr sacl, out IntPtr sd);
        [DllImport("advapi32.dll")]
        static extern uint GetSecurityDescriptorLength(IntPtr sd);
        [DllImport("kernel32.dll")]
        static extern IntPtr LocalFree(IntPtr p);
        [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        static extern bool MoveFileExW(string from, string to, uint flags);

        static bool OkSid(string s) { return s == "S-1-5-18" || s == "S-1-5-32-544"; }

        // null: guvenilir; aksi halde neden.
        public static string CheckDescriptor(RawSecurityDescriptor sd)
        {
            if (sd.Owner == null || !OkSid(sd.Owner.Value)) return "sahip SYSTEM/Administrators degil";
            if ((sd.ControlFlags & ControlFlags.DiscretionaryAclProtected) == 0) return "DACL korumali degil";
            if ((sd.ControlFlags & ControlFlags.DiscretionaryAclPresent) == 0 || sd.DiscretionaryAcl == null) return "DACL yok";
            foreach (GenericAce ace in sd.DiscretionaryAcl)
            {
                AceType t = ace.AceType;
                bool allow = t == AceType.AccessAllowed || t == AceType.AccessAllowedObject || t == AceType.AccessAllowedCallback
                    || t == AceType.AccessAllowedCallbackObject || t == AceType.AccessAllowedCompound;
                if (!allow) continue;
                KnownAce k = ace as KnownAce;
                if (k == null) return "taninmayan izin girdisi";
                if (OkSid(k.SecurityIdentifier.Value)) continue;
                if ((k.AccessMask & WriteMask) != 0) return k.SecurityIdentifier.Value + " yazabiliyor";
            }
            return null;
        }

        // Guvenilirse acik tutamac (cagiran kapatir), degilse null ve neden.
        public static SafeFileHandle OpenTrusted(string path, out string reason)
        {
            SafeFileHandle h = CreateFileW(path, FILE_LIST_DIRECTORY | READ_CONTROL | FILE_READ_ATTRIBUTES, FILE_SHARE_READ | FILE_SHARE_WRITE, IntPtr.Zero,
                OPEN_EXISTING, FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT, IntPtr.Zero);
            if (h.IsInvalid) { reason = "acilamadi (" + Marshal.GetLastWin32Error() + ")"; h.Dispose(); return null; }
            reason = Check(h);
            if (reason == null) return h;
            h.Dispose();
            return null;
        }

        static string Check(SafeFileHandle h)
        {
            FileInfo fi;
            if (!GetFileInformationByHandle(h, out fi)) return "oznitelik okunamadi";
            if ((fi.Attributes & ATTR_DIRECTORY) == 0) return "dizin degil";
            if ((fi.Attributes & ATTR_REPARSE) != 0) return "baglanti (reparse point)";
            IntPtr owner, group, dacl, sacl, sd;
            uint rc = GetSecurityInfo(h, SE_FILE_OBJECT, OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION,
                out owner, out group, out dacl, out sacl, out sd);
            if (rc != 0) return "guvenlik bilgisi okunamadi (" + rc + ")";
            try
            {
                byte[] bin = new byte[GetSecurityDescriptorLength(sd)];
                Marshal.Copy(sd, bin, 0, bin.Length);
                return CheckDescriptor(new RawSecurityDescriptor(bin, 0));
            }
            finally { LocalFree(sd); }
        }

        // Girdinin kendisini yeniden adlandirir (baglanti izlenmez, icerige girilmez).
        public static void MoveAside(string from, string to)
        {
            if (!MoveFileExW(from, to, 0)) throw new System.ComponentModel.Win32Exception(Marshal.GetLastWin32Error());
        }
    }
}
'@
}

function Open-TrustedDir([string]$dir) {
    $why = $null
    $h = [CortmedSetup.DirTrust]::OpenTrusted($dir, [ref]$why)
    if ($h) { return $h }
    return $null
}

# Guvenilmeyen girdiyi tek yeniden adlandirmayla kenara alir; yeni adi dondurur.
function Move-Aside([string]$dir) {
    # Zaman + rastgele ek: yeniden denemelerde ad cakismaz
    $to = '{0}.untrusted-{1}-{2}' -f $dir, (Get-Date -Format 'yyyyMMddHHmmss'), [Guid]::NewGuid().ToString('N').Substring(0, 8)
    [CortmedSetup.DirTrust]::MoveAside($dir, $to)
    return $to
}
# --- /kopya ---

# Onarim takimi: bu betik ve -Source'un istedigi her sey, -Source olarak kullanilabilecek duzende $to'ya
# (Program Files\Cortmed). Panel onarimda yalnizca bu, kullanicinin yazamadigi kopyayi yukseltir.
function Copy-RepairKit([string]$to, [string]$self, [string]$engineCs, [string[]]$csFiles, [string]$sysmonXml,
    [string]$rules, [string]$uninstaller, [string]$sigDir) {
    $kitGuard = Join-Path $to 'guard'
    # Eski kaynaklar kalmasin; rmdir /s baglantilari izlemez ($to yalnizca yoneticilerce yazilabilir)
    if (Test-Path -LiteralPath $kitGuard) { & (Join-Path ([Environment]::SystemDirectory) 'cmd.exe') /c rmdir /s /q "$kitGuard" | Out-Null }
    foreach ($d in 'Core', 'Service') { New-Item -ItemType Directory -Force (Join-Path $kitGuard $d) | Out-Null }
    foreach ($f in $csFiles) { Copy-Item -LiteralPath $f (Join-Path $kitGuard (Split-Path (Split-Path $f -Parent) -Leaf)) -Force }
    Copy-Item -LiteralPath $sysmonXml (Join-Path $kitGuard 'sysmon-cortmed.xml') -Force
    Copy-Item -LiteralPath $self (Join-Path $to 'Install-Guard.ps1') -Force
    Copy-Item -LiteralPath $engineCs (Join-Path $to 'CortmedEngine.cs') -Force
    Copy-Item -LiteralPath $rules (Join-Path $to 'behavior_rules.json') -Force
    Copy-Item -LiteralPath $uninstaller (Join-Path $to 'Uninstall-Guard.ps1') -Force
    foreach ($m in 'manifest.json', 'manifest.sig') {
        if ($sigDir) { Copy-Item -LiteralPath (Join-Path $sigDir $m) (Join-Path $to $m) -Force }
    }
}

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
# Onarim: kaynak Program Files\Cortmed'in kendisi (panel). Dosyalar zaten yerinde; yalnizca klasor guvenilirse calisir.
$fromApp = [string]::Equals($Source.TrimEnd('\'), $app.TrimEnd('\'), [StringComparison]::OrdinalIgnoreCase)

# Yonetici degilse ya da 64 bit Windows'ta 32 bit PowerShell ise (Program Files x86 olur) 64 bit PowerShell'i
# yonetici olarak yeniden baslat, profil yuklenmeden. UAC reddedilirse Start-Process istisna firlatir (cagirana gider).
if (-not $WhatIf) {
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
}

# Klasorlerin bu calismanin BASINDAKI durumu, tutamaclar calisma boyunca acik kalir. Isaretler yalnizca
# veri klasoru guvenilirse ve tutamac tutulurken okunur; guvenilmeyen klasor kenara alinir, isaretleri sayilmaz.
try { Add-DirTrustType }
catch {
    Write-Host "  Davranış bekçisi kurulamadı: $($_.Exception.Message)" -ForegroundColor Red
    if ($Elevated) { Read-Host '  Kapatmak için Enter' | Out-Null }
    exit 1
}
$appH = Open-TrustedDir $app
$dataH = Open-TrustedDir $data
if ($fromApp -and -not $appH -and -not $WhatIf) {
    # Kaynak klasor yoneticiye ozel degil: oradan derlenip hizmet olarak calistirilmaz
    if ($dataH) { $dataH.Dispose() }
    Write-Host "  Davranış bekçisi onarılamadı: $app güvenilir durumda değil. Cortmed Security'yi indirdiğiniz paketten yeniden kurun." -ForegroundColor Red
    if ($Elevated) { Read-Host '  Kapatmak için Enter' | Out-Null }
    exit 1
}
$oursMarked = $dataH -and (Test-Path -LiteralPath $markOurs)
if ($WhatIf -and $SysmonState -ne 'Auto') {
    $sysmonPresent = ($SysmonState -eq 'Present')
} else {
    $sysmonSvc = Get-Service Sysmon64, Sysmon -ErrorAction SilentlyContinue | Select-Object -First 1
    $sysmonPresent = [bool]$sysmonSvc
}
$sysmonOurs = $sysmonPresent -and $oursMarked
$guardExists = [bool](Get-Service $svcName -ErrorAction SilentlyContinue)

function Test-Entry([string]$p) { (New-Object IO.DirectoryInfo $p).Exists -or (New-Object IO.FileInfo $p).Exists }
function DirStep([string]$dir, $handle) {
    if ($handle) { "$dir korunuyor (zaten yalnızca yöneticiler yazabiliyor)" }
    elseif (Test-Entry $dir) { "$dir güvenilir durumda değil: içine dokunulmadan '$dir.untrusted-<zaman>' adıyla kenara alınacak ve yalnızca yöneticilerin yazabileceği şekilde yeniden oluşturulacak" }
    else { "$dir oluşturulacak; yalnızca yöneticiler ve sistem yazabilecek, kullanıcılar yalnızca okuyabilecek" }
}
$sysmonStep = if (-not $sysmonPresent) { "Sysmon kurulacak (Microsoft'un resmi Sysmon.zip dosyası indirilip imzası doğrulanacak)" }
elseif ($sysmonOurs) { 'Sysmon daha önce Cortmed tarafından kurulmuş; yalnızca ayarı güncellenecek' }
else { 'Sysmon önceden kurulu, dokunulmayacak' }
$plan = @(
    (DirStep $app $appH),
    (DirStep $data $dataH),
    "Bekçi kaynakları $app\src klasörüne kopyalanıp orada CortmedGuard.exe olarak derlenecek",
    "Kaldırma betiği $app\Uninstall-Guard.ps1 olarak kopyalanacak",
    $(if ($fromApp) { "Onarım: kaynak $app (yalnızca yöneticilerin yazabildiği kopya)" }
        else { "Onarım için kurulum dosyaları (Install-Guard.ps1, kaynaklar, kurallar, Sysmon ayarı) $app klasörüne kopyalanacak" }),
    "Davranış kuralları ve Sysmon ayarı $data klasörüne kopyalanacak",
    $sysmonStep,
    $(if ($guardExists) { 'CortmedGuard hizmeti durdurulup güncellenecek ve yeniden başlatılacak' }
        else { 'CortmedGuard hizmeti kurulacak (her açılışta başlar, çökerse yeniden başlar) ve başlatılacak' }))

if ($WhatIf) {
    if ($appH) { $appH.Dispose() }
    if ($dataH) { $dataH.Dispose() }
    Write-Host '  Davranış bekçisi kurulum planı (-WhatIf: hiçbir şey değiştirilmedi):'
    foreach ($s in $plan) { Write-Host "   - $s" }
    exit 0
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

# Guvenilir klasor (yukseltme) oldugu gibi kalir. Degilse kenara alinir (icine dokunulmaz) ve ACL'si olusturma
# aninda verilerek yeniden yaratilir; tutamac tabanli denetim gecmezse (arada ad kapildiysa) tekrar denenir.
function Initialize-SecureDir([string]$dir, $handle) {
    if ($handle) { return $handle }
    for ($i = 0; $i -lt 3; $i++) {
        if (Test-Entry $dir) {
            $aside = Move-Aside $dir
            Write-Host "  Güvenilir durumda olmayan eski klasör kenara alındı (içine dokunulmadı): $aside" -ForegroundColor Yellow
        }
        [IO.Directory]::CreateDirectory($dir, (New-ProtectedAcl)) | Out-Null
        $h = Open-TrustedDir $dir
        if ($h) { return $h }
        Start-Sleep -Milliseconds 200
    }
    throw "$dir güvenli olarak oluşturulamadı."
}

# Yalnizca yoneticilerin yazabildigi klasorlerin altindaki gecici klasorler icin; rmdir /s baglantilari izlemez
# Imza gecerli, imzalayan kurum (O=) tam olarak "Microsoft Corporation", imzalayan ad bilinen bir Microsoft adi
# ve zincir Microsoft kok sertifikasina varmali. (Sysmon 2026 itibariyla "Microsoft Windows Publisher" ile imzali.)
function Test-MicrosoftSigned($sig) {
    if (-not $sig -or $sig.Status -ne [Management.Automation.SignatureStatus]::Valid -or -not $sig.SignerCertificate) { return $false }
    $cert = $sig.SignerCertificate
    $parts = @($cert.Subject -split ',\s*')
    if ($parts -notcontains 'O=Microsoft Corporation') { return $false }
    $cn = $cert.GetNameInfo([Security.Cryptography.X509Certificates.X509NameType]::SimpleName, $false)
    if (@('Microsoft Corporation', 'Microsoft Windows Publisher', 'Microsoft Windows') -notcontains $cn) { return $false }
    $chain = New-Object Security.Cryptography.X509Certificates.X509Chain
    $chain.ChainPolicy.RevocationMode = [Security.Cryptography.X509Certificates.X509RevocationMode]::NoCheck
    if (-not $chain.Build($cert)) { return $false }
    $root = $chain.ChainElements[$chain.ChainElements.Count - 1].Certificate
    return ($root.Subject -match '^CN=Microsoft Root Certificate Authority( \d{4})?, O=Microsoft Corporation,')
}

function Remove-AdminDir([string]$p) {
    if (Test-Entry $p) { & $cmd /c rmdir /s /q "$p" | Out-Null }
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
$newExe = Join-Path $app 'CortmedGuard.new.exe'
try {
    Write-Host ''
    Write-Host '  CORTMED davranış bekçisi kuruluyor...' -ForegroundColor Cyan
    Set-Location $winDir
    # Modulleri PSModulePath yerine Windows PowerShell'in kendi klasorunden yukle
    # (Archive modulu kullanilmaz: tr-TR gibi dillerde yerellestirme dosyasi bulunamayip kurulumu durduruyor)
    Import-Module (Join-Path $PSHOME 'Modules\Microsoft.PowerShell.Security')

    # 1) Klasorler ve ACL (hizmet baslamadan once)
    $appH = Initialize-SecureDir $app $appH
    $dataH = Initialize-SecureDir $data $dataH
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
    Remove-AdminDir $srcDir
    New-Item -ItemType Directory $srcDir | Out-Null
    foreach ($f in $csFiles + $engineCs) { Copy-Item $f $srcDir -Force }
    $csc = Join-Path $winDir 'Microsoft.NET\Framework64\v4.0.30319\csc.exe'
    if (-not (Test-Path $csc)) { $csc = Join-Path $winDir 'Microsoft.NET\Framework\v4.0.30319\csc.exe' }
    $refs = 'System.dll', 'System.Core.dll', 'System.Xml.dll', 'System.Xml.Linq.dll', 'System.ServiceProcess.dll', 'System.Web.Extensions.dll'
    $cscArgs = @('/nologo', '/target:exe', '/platform:anycpu', '/optimize+', '/codepage:65001', "/out:$newExe") +
        ($refs | ForEach-Object { "/reference:$_" }) + @(Get-ChildItem $srcDir -Filter *.cs | ForEach-Object FullName)
    $out = & $csc @cscArgs
    if ($LASTEXITCODE -ne 0 -or -not (Test-Path $newExe)) { throw "CortmedGuard derlenemedi: $($out -join ' ')" }
    Write-Host '  [OK] CortmedGuard.exe derlendi' -ForegroundColor Green
    # Kaldirma betigi (Uninstall.ps1 yalnizca bu kopyayi yukseltir) ve onarim takimi (panel onarimda yalnizca
    # bu kopyayi yukseltir). Kaynak zaten Program Files\Cortmed ise dosyalar yerinde.
    if (-not $fromApp) {
        Copy-RepairKit $app $PSCommandPath $engineCs $csFiles $sysmonXml $rules $uninstaller $sigDir
        Write-Host '  [OK] Onarım dosyaları Program Files''a kopyalandı' -ForegroundColor Green
    }

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
            Remove-AdminDir $tmp
            New-Item -ItemType Directory $tmp | Out-Null
            Write-Host '  Sysmon indiriliyor (Microsoft Sysinternals)...'
            [Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12
            $zip = Join-Path $tmp 'Sysmon.zip'
            Invoke-WebRequest $sysmonUrl -OutFile $zip -UseBasicParsing
            Add-Type -AssemblyName System.IO.Compression.FileSystem
            [IO.Compression.ZipFile]::ExtractToDirectory($zip, $tmp)
            $s64 = Join-Path $tmp 'Sysmon64.exe'
            if (-not (Test-Path $s64)) { throw 'İndirilen pakette Sysmon64.exe yok; Sysmon kurulmadı.' }
            $sig = Get-AuthenticodeSignature $s64
            if (-not (Test-MicrosoftSigned $sig)) {
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
            Remove-AdminDir $tmp
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
        $why = $_.Exception.Message
        if ($existing) {
            Invoke-Sc "start $svcName" -AllowFail
            throw "CortmedGuard.exe değiştirilemedi (eski sürüm yeniden başlatıldı): $why"
        }
        throw "CortmedGuard.exe yerine konamadı: $why"
    }
    try {
        $bin = 'binPath= "\"' + $exe + '\""'
        if ($existing) { Invoke-Sc "config $svcName $bin start= auto obj= LocalSystem" }
        else { Invoke-Sc "create $svcName $bin start= auto obj= LocalSystem" }
        Invoke-Sc "failure $svcName reset= 86400 actions= restart/5000/restart/5000/restart/5000"
        Invoke-Sc "start $svcName"
    } catch {
        # Bir kez daha baslatmayi dene; yine de hatayi acikca bildir
        if (Get-Service $svcName -ErrorAction SilentlyContinue) { Invoke-Sc "start $svcName" -AllowFail }
        throw "CortmedGuard hizmeti ayarlanamadı veya başlatılamadı: $($_.Exception.Message)"
    }
    Write-Host '  [OK] CortmedGuard hizmeti çalışıyor' -ForegroundColor Green
} catch {
    # Yalnizca guvenilir Program Files klasorundeyse sil (guvenilmeyen klasore dokunulmaz)
    if ($appH) { Remove-Item -LiteralPath $newExe -Force -ErrorAction SilentlyContinue }
    Write-Host "  Davranış bekçisi kurulamadı: $($_.Exception.Message)" -ForegroundColor Red
    if ($appH) { $appH.Dispose() }
    if ($dataH) { $dataH.Dispose() }
    if ($Elevated) { Read-Host '  Kapatmak için Enter' | Out-Null }
    exit 1
}
if ($appH) { $appH.Dispose() }
if ($dataH) { $dataH.Dispose() }

if ($warn) {
    foreach ($w in $warn) { Write-Host "  $w" -ForegroundColor Yellow }
    Write-Host '  Davranış bekçisi Sysmon olmadan olayları göremez; daha sonra kurulumu yeniden çalıştırabilirsiniz.' -ForegroundColor Yellow
    if ($Elevated) { Read-Host '  Kapatmak için Enter' | Out-Null }
    exit 2
}
exit 0
