# Cortmed Sandbox otomatik deneme betigi. YALNIZCA Windows Sandbox icinde calisir (LogonCommand).
# Sonuclar Masaustu\Results klasorune yazilir: results.tsv, *.txt, *.png, done.txt
$ErrorActionPreference = 'Continue'
$desk = [Environment]::GetFolderPath('Desktop')
$kit = Join-Path $desk 'Cortmed'
$res = Join-Path $desk 'Results'
if ($env:USERNAME -ne 'WDAGUtilityAccount') { 'Bu betik yalnizca Windows Sandbox icinde calisir.'; exit 1 }
New-Item -ItemType Directory -Force $res | Out-Null
Start-Transcript (Join-Path $res 'transcript.txt') -Force | Out-Null
Add-Type -AssemblyName System.Windows.Forms, System.Drawing, UIAutomationClient, UIAutomationTypes

function Step([string]$name, [bool]$ok, [string]$detail = '') {
    $line = "{0}`t{1}`t{2}" -f $name, $(if ($ok) { 'OK' } else { 'FAIL' }), ($detail -replace '[\r\n\t]+', ' ')
    Add-Content (Join-Path $res 'results.tsv') $line -Encoding UTF8
    Write-Host $line
}
function Shot([string]$name) {
    try {
        $b = [Windows.Forms.SystemInformation]::VirtualScreen
        $bmp = New-Object Drawing.Bitmap $b.Width, $b.Height
        $g = [Drawing.Graphics]::FromImage($bmp)
        $g.CopyFromScreen($b.Left, $b.Top, 0, 0, $bmp.Size)
        $bmp.Save((Join-Path $res "$name.png"), [Drawing.Imaging.ImageFormat]::Png)
        $g.Dispose(); $bmp.Dispose()
    } catch { Write-Host "shot $name : $_" }
}
function Find-Window([string]$titlePrefix, [int]$timeoutSec) {
    # Pencere basligindan surec penceresini bul (UIA kok taramasi asili pencerelerde zaman asimina ugruyor)
    $sw = [Diagnostics.Stopwatch]::StartNew()
    while ($sw.Elapsed.TotalSeconds -lt $timeoutSec) {
        foreach ($p in Get-Process) {
            try {
                if ($p.MainWindowHandle -ne [IntPtr]::Zero -and $p.MainWindowTitle -like "$titlePrefix*") {
                    return [Windows.Automation.AutomationElement]::FromHandle($p.MainWindowHandle)
                }
            } catch { }
        }
        Start-Sleep -Milliseconds 500
    }
    return $null
}
function Click-Button($win, [string]$name) {
    $c = New-Object Windows.Automation.PropertyCondition([Windows.Automation.AutomationElement]::NameProperty, $name)
    # Ad ile baslayan ilk dugme; Invoke olmazsa Win32 BM_CLICK
    $btn = $null
    try {
        $bc = New-Object Windows.Automation.PropertyCondition([Windows.Automation.AutomationElement]::ControlTypeProperty, [Windows.Automation.ControlType]::Button)
        foreach ($b in $win.FindAll([Windows.Automation.TreeScope]::Descendants, $bc)) {
            Write-Host ("dugme: " + $b.Current.Name)
            if ($b.Current.Name -like "$name*") { $btn = $b; break }
        }
    } catch { Write-Host "FindAll: $_" }
    if (-not $btn) { return $false }
    $p = $null
    try { if ($btn.TryGetCurrentPattern([Windows.Automation.InvokePattern]::Pattern, [ref]$p)) { $p.Invoke(); return $true } } catch { Write-Host "Invoke: $_" }
    $h = $btn.Current.NativeWindowHandle
    if ($h) {
        if (-not ('W32Click' -as [type])) { Add-Type 'using System; using System.Runtime.InteropServices; public static class W32Click { [DllImport("user32.dll")] public static extern IntPtr SendMessage(IntPtr h, int m, IntPtr w, IntPtr l); }' }
        [void][W32Click]::SendMessage([IntPtr]$h, 0x00F5, [IntPtr]::Zero, [IntPtr]::Zero); return $true
    }
    return $false
}

try {
    # 1) Paketi cikar ve kur
    $pkg = Join-Path $desk 'pkg'
    Expand-Archive (Join-Path $kit 'CortmedSecurity-Windows.zip') $pkg -Force
    $inst = Start-Process powershell.exe -ArgumentList '-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', (Join-Path $pkg 'Install.ps1') `
        -RedirectStandardOutput (Join-Path $res 'install-out.txt') -RedirectStandardError (Join-Path $res 'install-err.txt') -PassThru
    if (-not $inst.WaitForExit(900000)) { Step 'kurulum bitti' $false 'zaman asimi (15 dk)'; $inst.Kill() } else { Step 'kurulum bitti' $true "kod $($inst.ExitCode)" }
    Start-Sleep 5
    $installOut = Get-Content (Join-Path $res 'install-out.txt') -Raw -ErrorAction SilentlyContinue

    # 2) Hizmetler ve izinler
    $g = Get-Service CortmedGuard -ErrorAction SilentlyContinue
    Step 'CortmedGuard hizmeti calisiyor' ($g -and $g.Status -eq 'Running') "$($g.Status)"
    $s = Get-Service Sysmon64 -ErrorAction SilentlyContinue
    Step 'Sysmon64 hizmeti calisiyor' ($s -and $s.Status -eq 'Running') "$($s.Status)"
    $acl = (& icacls 'C:\Program Files\Cortmed') -join ' '
    Step 'Program Files\Cortmed kullanicilar yazamaz' ($acl -notmatch 'BUILTIN\\Users:\(OI\)\(CI\)\((F|M|W)') $acl
    Step 'YARA calisiyor (VCRUNTIME)' ((& (Join-Path $env:LOCALAPPDATA 'CortmedSecurity\engines\yara\yara64.exe') -v 2>&1) -match '^\d') ''
    Step 'kurulum ciktisinda hata yok' ($installOut -notmatch 'kurulamad|hata|error') ''

    # 3) Panel
    $exe = Join-Path $env:LOCALAPPDATA 'CortmedSecurity\CortmedSecurity.exe'
    if (Test-Path $exe) { Start-Process $exe } else { Start-Process powershell.exe -ArgumentList '-NoProfile', '-ExecutionPolicy', 'Bypass', '-WindowStyle', 'Hidden', '-File', (Join-Path $env:LOCALAPPDATA 'CortmedSecurity\CortmedSecurity.ps1'), '-Mode', 'Panel' }
    $panel = Find-Window 'Cortmed Security' 60
    Step 'panel acildi' ($null -ne $panel) ''
    Start-Sleep 8; Shot '02-panel'

    # 4) "Oraya goturen" dugme hedefi
    # Cortmed'in kendi eylem kodu: Windows Guvenligi yoksa Ayarlar'daki sayfaya duser
    $appPs = Join-Path $env:LOCALAPPDATA 'CortmedSecurity\CortmedSecurity.ps1'
    $act = Start-Process powershell.exe -ArgumentList '-NoProfile', '-ExecutionPolicy', 'Bypass', '-Command',
        ". '$appPs' -Mode Lib; Invoke-FindingAction (Get-FindingAction ([pscustomobject]@{ key='defender-off'; level='RED'; title='x'; detail='x'; path='' }))" -PassThru
    [void]$act.WaitForExit(30000)
    Start-Sleep 8; Shot '03-defender-ayarlari'
    $opened = (Get-Process SecHealthUI, SystemSettings -ErrorAction SilentlyContinue)
    Step 'Virus korumasini ac dugmesi bir ayar penceresi acti' ($null -ne $opened) (($opened | ForEach-Object Name) -join ',')
    $opened | Stop-Process -Force -ErrorAction SilentlyContinue
    Start-Process 'ms-settings:windowsupdate'; Start-Sleep 6; Shot '03b-windows-update'
    Get-Process SystemSettings -ErrorAction SilentlyContinue | Stop-Process -Force -ErrorAction SilentlyContinue

    $dl = Join-Path $env:USERPROFILE 'Downloads'
    New-Item -ItemType Directory -Force $dl | Out-Null

    # 5a) Kirmizi uyari katmani (klasorde goster): once diger pencereleri kucult
    (New-Object -ComObject Shell.Application).MinimizeAll()
    Start-Sleep 2
    $bad = Join-Path $dl 'fatura_2024.pdf.exe'
    Copy-Item (Join-Path $kit 'CortmedBehaviorTest.exe') $bad -Force
    Start-Process (Join-Path $env:windir 'explorer.exe') -ArgumentList "/select,`"$bad`""
    Start-Sleep 3
    Start-Process powershell.exe -ArgumentList '-NoProfile', '-ExecutionPolicy', 'Bypass', '-WindowStyle', 'Hidden', '-File', (Join-Path $env:LOCALAPPDATA 'CortmedSecurity\CortmedSecurity.ps1'), '-Mode', 'Overlay', '-Path', "`"$bad`""
    Start-Sleep 3; Shot '06-kirmizi-katman'
    Start-Sleep 7
    Get-Process explorer -ErrorAction SilentlyContinue | Where-Object { $_.MainWindowTitle } | ForEach-Object { $_.CloseMainWindow() | Out-Null }
    Remove-Item $bad -Force -ErrorAction SilentlyContinue

    # 5b) Davranis bekcisi: zararsiz deneme programi
    Copy-Item (Join-Path $kit 'CortmedBehaviorTest.exe') $dl -Force
    $tp = Start-Process (Join-Path $dl 'CortmedBehaviorTest.exe') -PassThru
    $prompt = Find-Window 'Cortmed şüpheli bir programı durdurdu' 30
    Step 'soru penceresi cikti' ($null -ne $prompt) ''
    Shot '04-soru-penceresi'
    $log = Get-Content 'C:\ProgramData\Cortmed\guard.log' -Tail 40 -Encoding UTF8 -ErrorAction SilentlyContinue
    $log | Set-Content (Join-Path $res 'guard-log.txt') -Encoding UTF8
    Step 'guard.log dondurma kaydi' (($log -join ' ') -match 'donduruldu') ''
    $susp = $false
    try { $susp = @((Get-Process -Id $tp.Id).Threads | Where-Object { $_.WaitReason -eq 'Suspended' }).Count -gt 0 } catch { }
    Step 'deneme programi donduruldu' $susp ''
    if ($prompt) {
        Step 'Programi kapat tiklandi' (Click-Button $prompt 'Programı kapat') ''
        Start-Sleep 6
        Step 'deneme programi kapandi' ($null -eq (Get-Process -Id $tp.Id -ErrorAction SilentlyContinue)) ''
        Shot '05-kapatildiktan-sonra'
    }
    & (Join-Path $dl 'CortmedBehaviorTest.exe') --cleanup | Out-Null


    # 6) Kendi motorumuz: zip icindeki EICAR test dosyasi (Sandbox'ta Defender kapali; yakalayan Cortmed olmali)
    #    Imza parcalardan birlestirilir; bu betik dosyasinin kendisi test dosyasi sanilmasin.
    try {
        Add-Type -AssemblyName System.IO.Compression, System.IO.Compression.FileSystem
        $eic = 'X5O!P%@AP[4\PZX54(P^)7CC)7}' + '$EICAR-STANDARD-ANTIVIRUS' + '-TEST-FILE!$H+H*'
        $zd = Join-Path $env:TEMP ('eic-' + [guid]::NewGuid().ToString('N')); New-Item -ItemType Directory $zd | Out-Null
        [IO.File]::WriteAllText((Join-Path $zd 'eicar.com'), $eic)
        $ez = Join-Path $dl 'eicar_com.zip'
        if (Test-Path $ez) { Remove-Item $ez -Force }
        [IO.Compression.ZipFile]::CreateFromDirectory($zd, $ez)
        $js = & powershell.exe -NoProfile -ExecutionPolicy Bypass -File $appPs -Mode ScanFile -Json -Path $ez 2>&1 | Select-Object -Last 1
        Set-Content (Join-Path $res 'eicar-scan.txt') $js -Encoding UTF8
        Step 'Cortmed zip icindeki EICAR dosyasini yakaladi' ("$js" -match '"level":"RED"') "$js"
        # Tarayici koprusu ayni dosya icin RED dondurmeli (eklentinin indirme kontrolu yolu)
        $hostExe = Join-Path $env:LOCALAPPDATA 'CortmedSecurity\CortmedBrowserHost.exe'
        if (Test-Path $hostExe) {
            $psi = New-Object Diagnostics.ProcessStartInfo $hostExe
            $psi.UseShellExecute = $false; $psi.RedirectStandardInput = $true; $psi.RedirectStandardOutput = $true
            $hp = [Diagnostics.Process]::Start($psi)
            $body = [Text.Encoding]::UTF8.GetBytes((@{ path = $ez } | ConvertTo-Json -Compress))
            $in = $hp.StandardInput.BaseStream
            $in.Write([BitConverter]::GetBytes([int]$body.Length), 0, 4); $in.Write($body, 0, $body.Length); $in.Flush(); $in.Close()
            $out = $hp.StandardOutput.BaseStream
            $lenB = New-Object byte[] 4; [void]$out.Read($lenB, 0, 4)
            $len = [BitConverter]::ToInt32($lenB, 0)
            $buf = New-Object byte[] $len; $got = 0
            while ($got -lt $len) { $n = $out.Read($buf, $got, $len - $got); if ($n -le 0) { break }; $got += $n }
            [void]$hp.WaitForExit(150000)
            $reply = [Text.Encoding]::UTF8.GetString($buf, 0, $got)
            Set-Content (Join-Path $res 'host-reply.txt') $reply -Encoding UTF8
            Step 'tarayici koprusu EICAR icin RED dondu' ($reply -match '"level":"RED"') $reply
        } else { Step 'tarayici koprusu kurulu' $false $hostExe }
        Remove-Item $zd -Recurse -Force -ErrorAction SilentlyContinue
    } catch { Step 'EICAR denemesi' $false "$_" }

    # 7) Kaldirma
    $un = Start-Process powershell.exe -ArgumentList '-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', (Join-Path $env:LOCALAPPDATA 'CortmedSecurity\Uninstall.ps1') `
        -RedirectStandardOutput (Join-Path $res 'uninstall-out.txt') -PassThru
    [void]$un.WaitForExit(300000)
    Start-Sleep 10
    Step 'kaldirma: CortmedGuard yok' ($null -eq (Get-Service CortmedGuard -ErrorAction SilentlyContinue)) ''
    Step 'kaldirma: Sysmon64 yok' ($null -eq (Get-Service Sysmon64 -ErrorAction SilentlyContinue)) ''
    Step 'kaldirma: Program Files\Cortmed yok' (-not (Test-Path 'C:\Program Files\Cortmed')) ''
} catch {
    Step 'betik hatasi' $false "$_"
} finally {
    Stop-Transcript | Out-Null
    Set-Content (Join-Path $res 'done.txt') (Get-Date -Format o)
}
