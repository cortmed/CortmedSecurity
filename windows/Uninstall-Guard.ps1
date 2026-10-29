#Requires -Version 5.1
<#
  Cortmed Security - davranis bekcisi kaldirma (yonetici yetkisi ister)
  Kurulum bu betigi C:\Program Files\Cortmed icine koyar; Uninstall.ps1 yalnizca o kopyayi yukseltir.
    * CortmedGuard hizmetini durdurur ve siler
    * Sysmon'u yalnizca Cortmed kurduysa (guvenilir veri klasorunde sysmon-installed-by-cortmed isareti) kaldirir
    * Guvenilir (tutamac tabanli denetim) Program Files\Cortmed ve ProgramData\Cortmed klasorlerini siler;
      guvenilir olmayani silmez, "<ad>.untrusted-<zaman>" olarak kenara alir
  Yollar ortam degiskenlerinden degil, [Environment]'tan alinir.
#>
$ErrorActionPreference = 'Continue'
$winDir = [Environment]::GetFolderPath('Windows')
$sysDir = [Environment]::SystemDirectory
$app = Join-Path ([Environment]::GetFolderPath('ProgramFiles')) 'Cortmed'
$data = Join-Path ([Environment]::GetFolderPath('CommonApplicationData')) 'Cortmed'
$svcName = 'CortmedGuard'
$sc = Join-Path $sysDir 'sc.exe'
$cmd = Join-Path $sysDir 'cmd.exe'

# --- Klasor guveni. AYNI uc fonksiyon Uninstall-Guard.ps1'de de var (ayri dosya yerine kopya;
#     test ikisinin ayni oldugunu denetler). Degistirirseniz ikisini birlikte degistirin. ---
# Guvenilir: dizin, baglanti (reparse point) degil, sahibi SYSTEM veya Administrators, DACL korumali
# ve SYSTEM/Administrators disinda hicbir SID'e yazma izni yok. Hepsi TEK bir tutamactan okunur;
# tutamac FILE_SHARE_DELETE vermeden acik tutuldugu surece klasor yeniden adlandirilamaz/degistirilemez.
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
        const uint READ_CONTROL = 0x00020000, FILE_READ_ATTRIBUTES = 0x80;
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
            SafeFileHandle h = CreateFileW(path, READ_CONTROL | FILE_READ_ATTRIBUTES, FILE_SHARE_READ | FILE_SHARE_WRITE, IntPtr.Zero,
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
    $to = '{0}.untrusted-{1}' -f $dir, (Get-Date -Format 'yyyyMMddHHmmss')
    [CortmedSetup.DirTrust]::MoveAside($dir, $to)
    return $to
}
# --- /kopya ---

$me = [Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()
if (-not $me.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Host 'Davranış bekçisini kaldırmak için yönetici izni gerekiyor.' -ForegroundColor Yellow
    exit 1
}

# Betik kaldirilacak klasorun icinde; oradan cik
Set-Location $winDir
Add-DirTrustType

$svc = Get-Service $svcName -ErrorAction SilentlyContinue
if ($svc) {
    if ($svc.Status -ne 'Stopped') {
        & $sc stop $svcName | Out-Null
        try { $svc.WaitForStatus('Stopped', [TimeSpan]::FromSeconds(30)) } catch { }
    }
    Get-Process CortmedGuard -ErrorAction SilentlyContinue | Stop-Process -Force -ErrorAction SilentlyContinue
    & $sc delete $svcName | Out-Null
    if ($LASTEXITCODE -eq 0) { Write-Host 'CortmedGuard hizmeti kaldırıldı.' }
    else { Write-Host "CortmedGuard hizmeti silinemedi (kod $LASTEXITCODE)." -ForegroundColor Yellow }
}

$dataH = Open-TrustedDir $data
$appH = Open-TrustedDir $app

# Sysmon'a yalnizca onu biz kurduysak dokunulur: veri klasoru guvenilir VE isaret var (tutamac tutulurken okunur).
# Sysmon kendini %windir% altina kopyalar.
if ($dataH -and (Test-Path -LiteralPath (Join-Path $data 'sysmon-installed-by-cortmed'))) {
    $sm = Join-Path $winDir 'Sysmon64.exe'
    if (Test-Path $sm) {
        & $sm -u | Out-Null
        if ($LASTEXITCODE -eq 0) { Write-Host 'Sysmon kaldırıldı.' }
        else { Write-Host "Sysmon kaldırılamadı (kod $LASTEXITCODE)." -ForegroundColor Yellow }
    }
}

# Guvenilir klasor: icerigi yalnizca yoneticilerce yazilabildigi icin tutamac birakilip rmdir /s ile silinir
# (rmdir baglantilari izlemez). Guvenilmeyen: silinmez, kenara alinir.
function Remove-OrMoveAside([string]$dir, $handle) {
    if ($handle) {
        $handle.Dispose()
        & $cmd /c rmdir /s /q "$dir" | Out-Null
    } elseif ((New-Object IO.DirectoryInfo $dir).Exists -or (New-Object IO.FileInfo $dir).Exists) {
        try { Write-Host "Güvenilir durumda olmayan klasör silinmedi, kenara alındı: $(Move-Aside $dir)" -ForegroundColor Yellow }
        catch { Write-Host "Güvenilir durumda olmayan klasör silinmedi: $dir ($($_.Exception.Message))" -ForegroundColor Yellow }
    }
}
Remove-OrMoveAside $data $dataH
$appWasTrusted = [bool]$appH
Remove-OrMoveAside $app $appH
# Silinemeyen kaldiysa (or. bu betik kullanimdaysa) kisa bir gecikmeyle cmd silsin; rmdir /s baglantilari izlemez
if ($appWasTrusted -and (Test-Path -LiteralPath $app)) {
    Start-Process $cmd -WindowStyle Hidden -WorkingDirectory $winDir `
        -ArgumentList ('/c ping -n 4 127.0.0.1 >nul & rmdir /s /q "{0}"' -f $app)
}
if (Test-Path -LiteralPath $data) { Write-Host "Bazı dosyalar silinemedi: $data" -ForegroundColor Yellow }
Write-Host 'Davranış bekçisi kaldırıldı.'
exit 0
