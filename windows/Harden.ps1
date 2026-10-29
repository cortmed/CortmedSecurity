#Requires -Version 5.1
<#
  Cortmed Security - Guvenligi Guclendir (yonetici yetkisi gerekir)

  Windows'un ucretsiz ama varsayilan olarak kapali korumalarini acar:
    * Defender: istenmeyen uygulama (PUA) engelleme, ag korumasi, imza guncellemesi
    * Saldiri yuzeyi azaltma (ASR) kurallari: token / sifre calan virusleri hedefler
    * Guvenlik duvari: tum profiller acik
    * Istege bagli: Cloudflare guvenli DNS (zararli ve dolandirici siteleri engeller)

  -Auto: soru sormadan hepsini uygular (Cortmed panelindeki "Tek tikla ac" dugmesi)
  Geri almak icin:  Harden.ps1 -Undo
#>
param([switch]$Undo, [switch]$Auto)

$ErrorActionPreference = 'Continue'
$admin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole(
    [Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $admin) {
    $argList = @('-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', ('"{0}"' -f $MyInvocation.MyCommand.Path))
    if ($Undo) { $argList += '-Undo' }
    if ($Auto) { $argList += '-Auto' }
    Start-Process powershell.exe -Verb RunAs -ArgumentList $argList
    return
}

# Kural kimlikleri: https://learn.microsoft.com/defender-endpoint/attack-surface-reduction-rules-reference
$AsrRules = [ordered]@{
    'd3e037e1-3eb8-44c8-a917-57927947596d' = @(1, 'JavaScript/VBScript indirilen programı başlatamaz')
    '5beb7efe-fd9a-4556-801d-275e5ffc04cc' = @(1, 'Gizlenmiş (obfuscated) scriptler engellenir')
    '9e6c4e1f-7d60-472f-ba1a-a39ef669e4b2' = @(1, 'Windows şifre deposundan (LSASS) şifre çalma engellenir')
    'e6db77e5-3df2-4cf1-b95a-636979351e5b' = @(1, 'WMI ile gizli kalıcılık engellenir')
    'b2b3f03d-6a65-4f7b-a9c7-1c7ef74a9ba4' = @(1, 'USB bellekten imzasız program çalışamaz')
    '01443614-cd74-433a-b99e-2ecdc07bfc25' = @(6, 'Yeni ve az bilinen programlar için UYARI verilir (izin verebilirsin)')
}
$SafeDns = @('1.1.1.2', '1.0.0.2')

function Step([string]$name, [scriptblock]$action) {
    try {
        & $action
        Write-Host "  [OK]   $name" -ForegroundColor Green
    } catch {
        Write-Host "  [HATA] $name : $($_.Exception.Message)" -ForegroundColor Red
    }
}

function Get-ActiveAdapters {
    Get-NetAdapter | Where-Object { $_.Status -eq 'Up' -and -not $_.Virtual }
}

Write-Host ''
Write-Host '  CORTMED SECURITY - Güvenliği Güçlendir' -ForegroundColor Cyan
Write-Host '  ======================================' -ForegroundColor Cyan
Write-Host ''

if ($Undo) {
    Write-Host '  Cortmed ayarları geri alınıyor...'
    Step 'ASR kuralları kaldırıldı' {
        Remove-MpPreference -AttackSurfaceReductionRules_Ids ([string[]]$AsrRules.Keys) -ErrorAction Stop
    }
    Step 'DNS otomatik (DHCP) ayara döndü' {
        foreach ($a in Get-ActiveAdapters) { Set-DnsClientServerAddress -InterfaceIndex $a.ifIndex -ResetServerAddresses }
    }
    Write-Host ''
    Write-Host '  Defender PUA / ağ koruması ve güvenlik duvarı açık bırakıldı (zararsızdır).'
    Read-Host '  Kapatmak için Enter'
    return
}

Write-Host '  Şunlar yapılacak:'
Write-Host '   1. Defender: istenmeyen uygulama engelleme + ağ koruması açılır, imzalar güncellenir'
Write-Host '   2. Token/şifre çalan virüslere karşı Microsoft ASR kuralları:'
foreach ($r in $AsrRules.Values) { Write-Host "        - $($r[1])" }
Write-Host '   3. Güvenlik duvarı tüm ağlarda açılır'
Write-Host ''
$go = if ($Auto) { 'E' } else { Read-Host '  Devam edilsin mi? (E/H)' }
if ($go -notmatch '^[EeYy]') { Write-Host '  İptal edildi.'; Start-Sleep 2; return }

Write-Host ''
Step 'Defender imzaları güncellendi' { Update-MpSignature -ErrorAction Stop }
Step 'İstenmeyen uygulama (PUA) engelleme açıldı' { Set-MpPreference -PUAProtection Enabled -ErrorAction Stop }
Step 'Ağ koruması açıldı (zararlı sitelere bağlantı engellenir)' {
    Set-MpPreference -EnableNetworkProtection Enabled -ErrorAction Stop
}
Step 'Bulut koruması ve otomatik örnek gönderimi açık' {
    Set-MpPreference -MAPSReporting Advanced -SubmitSamplesConsent SendSafeSamples -ErrorAction Stop
}
Step 'ASR kuralları açıldı' {
    Add-MpPreference -AttackSurfaceReductionRules_Ids ([string[]]$AsrRules.Keys) `
        -AttackSurfaceReductionRules_Actions ([int[]]($AsrRules.Values | ForEach-Object { $_[0] })) -ErrorAction Stop
}
Step 'Güvenlik duvarı açık' { Set-NetFirewallProfile -All -Enabled True -ErrorAction Stop }

Write-Host ''
Write-Host '  İsteğe bağlı: Cloudflare güvenli DNS (1.1.1.2). Virüslü ve dolandırıcı siteleri açılmadan engeller.'
Write-Host '  Şirket/okul ağında bazı iç siteler açılmayabilir; o durumda "Harden.ps1 -Undo" ile geri alınır.'
$dns = if ($Auto) { 'E' } else { Read-Host '  Güvenli DNS açılsın mı? (E/H)' }
if ($dns -match '^[EeYy]') {
    Step 'Güvenli DNS ayarlandı (1.1.1.2 / 1.0.0.2)' {
        foreach ($a in Get-ActiveAdapters) { Set-DnsClientServerAddress -InterfaceIndex $a.ifIndex -ServerAddresses $SafeDns -ErrorAction Stop }
        Clear-DnsClientCache
    }
}

Write-Host ''
Write-Host '  Bitti. Cortmed sonucu birazdan kendiliğinden gösterecek.' -ForegroundColor Cyan
if ($Auto) { Start-Sleep 3 } else { Read-Host '  Kapatmak için Enter' }
