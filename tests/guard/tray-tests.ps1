# Tepsi (CortmedSecurity.ps1 -Mode Lib) davranis bekcisi testleri. run.ps1 ayri bir powershell'de calistirir.
# Hicbir pencere gosterilmez: formlar kurulur, Show/ShowDialog cagrilmaz. Betik gecici bir kopyadan yuklenir
# (Lib modu calisma klasorunde data\ ve Karantina\ acar; depo kirlenmesin).
param([string]$RepoRoot)
$ErrorActionPreference = 'Stop'
$script:trayFails = 0
function TCheck([string]$name, [bool]$ok, [string]$why = '') {
    if ($ok) { Write-Host "PASS $name" } else { Write-Host "FAIL $name $why"; $script:trayFails++ }
}

$work = Join-Path ([IO.Path]::GetTempPath()) ('cortmed-traytest-' + [Guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Force $work | Out-Null
try {
    foreach ($f in 'CortmedSecurity.ps1', 'CortmedEngine.cs') { Copy-Item (Join-Path $RepoRoot "windows\$f") $work }
    . (Join-Path $work 'CortmedSecurity.ps1') -Mode Lib
    $ErrorActionPreference = 'Stop'

    $GuardDataDir = Join-Path $work 'guarddata'
    New-Item -ItemType Directory -Force $GuardDataDir | Out-Null

    function All-Controls($c) { foreach ($x in $c.Controls) { $x; All-Controls $x } }
    # Gosterilmemis formda PerformClick calismaz (CanSelect false); Click olayini dogrudan tetikle
    function Click($b) { $b.GetType().GetMethod('OnClick', [Reflection.BindingFlags]'NonPublic,Instance').Invoke($b, @([EventArgs]::Empty)) }
    function Btn($form, [string]$text) { @(All-Controls $form | Where-Object { $_ -is [Windows.Forms.Button] -and $_.Text -eq $text }) | Select-Object -First 1 }

    $killText = 'Programı kapat (önerilen)'
    $allowText = 'İzin ver, devam etsin'
    $json = '{"type":"ask","id":"p1","program":"kotu.exe","path":"C:\\Users\\x\\Downloads\\kotu.exe","publisher":"","score":120,"reasons":["Belgelerinizi hızla değiştiriyor","Gölge kopyaları silmeye çalıştı"]}'

    # 1) Baslik, dugmeler, nedenler
    $calls = New-Object Collections.ArrayList
    $answer = { param($id, $decision) [void]$calls.Add("$id|$decision"); $true }
    $p = $json | ConvertFrom-Json
    $f = $null
    try { $f = New-GuardPromptForm $p $answer } catch { Write-Host "  New-GuardPromptForm: $($_.Exception.Message)" }
    TCheck 'soru penceresi kuruldu' ($f -ne $null)
    if ($f) {
        TCheck 'soru penceresi basligi' ($f.Text -eq 'Cortmed şüpheli bir programı durdurdu: kotu.exe') $f.Text
        $btnTexts = @(All-Controls $f | Where-Object { $_ -is [Windows.Forms.Button] } | ForEach-Object Text)
        TCheck 'dugme: Programi kapat (onerilen)' ($btnTexts -contains $killText) ($btnTexts -join ' / ')
        TCheck 'dugme: Izin ver, devam etsin' ($btnTexts -contains $allowText) ($btnTexts -join ' / ')
        TCheck 'dugme: Ayrintilar' ($btnTexts -contains 'Ayrıntılar') ($btnTexts -join ' / ')
        $texts = (@(All-Controls $f | ForEach-Object Text) -join "`n")
        TCheck 'nedenler gosteriliyor' ($texts.Contains('Belgelerinizi hızla değiştiriyor') -and $texts.Contains('Gölge kopyaları silmeye çalıştı')) ''
        TCheck 'soru penceresi en ustte' ($f.TopMost) ''
        TCheck 'soru penceresi gosterilmedi' (-not $f.Visible) ''

        # 2) Dugmeler (id, karar) gonderir
        Click (Btn $f $killText)
        TCheck 'kapat dugmesi (p1,kill) gonderir' (($calls -join ',') -eq 'p1|kill') ($calls -join ',')
    }
    $calls.Clear()
    $f2 = New-GuardPromptForm $p $answer
    Click (Btn $f2 $allowText)
    TCheck 'izin dugmesi (p1,allow) gonderir' (($calls -join ',') -eq 'p1|allow') ($calls -join ',')
    $calls.Clear()
    $f3 = New-GuardPromptForm $p $answer
    $f3.Close(); $f3.Dispose()
    TCheck 'pencereyi kapatmak cevap gondermez' ($calls.Count -eq 0) ($calls -join ',')

    # 3) Ayni id iki kez: tek pencere; cevaplanan id yok sayilir
    $calls.Clear()
    $st = New-GuardState
    $g1 = Receive-GuardPrompt $st $json $answer -NoShow
    $g2 = Receive-GuardPrompt $st $json $answer -NoShow
    TCheck 'ayni id: ilk gelis pencere kurar' ($g1 -ne $null) ''
    TCheck 'ayni id: ikinci gelis pencere kurmaz' ($g2 -eq $null) ''
    TCheck 'ayni id: tek acik pencere' ($st.open.Count -eq 1) "$($st.open.Count)"
    if ($g1) { Click (Btn $g1 $killText) }
    TCheck 'ayni id: cevap bir kez gonderildi' (($calls -join ',') -eq 'p1|kill') ($calls -join ',')
    $g3 = Receive-GuardPrompt $st $json $answer -NoShow
    TCheck 'cevaplanan id yok sayilir' ($g3 -eq $null) ''
    TCheck 'cevaplanan id: acik pencere kalmadi' ($st.open.Count -eq 0) "$($st.open.Count)"
    # Cevapsiz kapatilan soru yeniden gelirse (yeniden baglanti) tekrar sorulur
    $json2 = $json.Replace('"p1"', '"p2"')
    $h1 = Receive-GuardPrompt $st $json2 $answer -NoShow
    if ($h1) { $h1.Close() }
    $h2 = Receive-GuardPrompt $st $json2 $answer -NoShow
    TCheck 'cevapsiz kapatilan soru yeniden gelince sorulur' ($h2 -ne $null) ''
    TCheck 'bozuk soru yok sayilir' ((Receive-GuardPrompt $st '{bozuk' $answer -NoShow) -eq $null) ''
    TCheck 'id''siz soru yok sayilir' ((Receive-GuardPrompt $st '{"type":"ask","program":"a.exe"}' $answer -NoShow) -eq $null) ''
    # Cevap false (program artik yok): pencere kapanir, id cevaplanmis sayilir
    $st2 = New-GuardState
    $k = Receive-GuardPrompt $st2 $json.Replace('"p1"', '"p3"') { param($id, $d) $false } -NoShow
    if ($k) { Click (Btn $k $killText) }
    TCheck 'cevap false: pencere kapandi' ($k -and $k.IsDisposed -and $st2.open.Count -eq 0) ''
    TCheck 'cevap false: id cevaplanmis' ($st2.answered.ContainsKey('p3')) ''
    # Baglanti yokken ('keep'): pencere acik kalir, id cevaplanmamis
    $m = Receive-GuardPrompt $st2 $json.Replace('"p1"', '"p4"') { param($id, $d) 'keep' } -NoShow
    if ($m) { Click (Btn $m $killText) }
    TCheck 'cevap keep: pencere acik kalir' ($m -and -not $m.IsDisposed -and $st2.open.ContainsKey('p4') -and -not $st2.answered.ContainsKey('p4')) ''
    # 10 dakika cevapsiz: id basina bir kez hatirlatma
    $now = Get-Date
    $due1 = @(Get-GuardOverdue $st2 $now.AddMinutes(5))
    $due2 = @(Get-GuardOverdue $st2 $now.AddMinutes(11))
    $due3 = @(Get-GuardOverdue $st2 $now.AddMinutes(20))
    TCheck '10 dakikadan once hatirlatma yok' ($due1.Count -eq 0) ($due1 -join ',')
    TCheck '10 dakika: cevapsiz id icin bir hatirlatma' (($due2 -join ',') -eq 'p4') ($due2 -join ',')
    TCheck 'hatirlatma id basina bir kez' ($due3.Count -eq 0) ($due3 -join ',')

    # 4) findings.json davranis bulgulari tehditlerde
    $fj = Join-Path $GuardDataDir 'findings.json'
    $finding = '[{"key":"behavior:' + ('a' * 64) + '","level":"RED","title":"Durdurulan program: kotu.exe","detail":"Belgelerinizi hızla değiştiriyor","path":"C:\\x\\kotu.exe","tab":"threat","report":"Program: C:\\x\\kotu.exe"}]'
    [IO.File]::WriteAllText($fj, $finding, (New-Object Text.UTF8Encoding($false)))
    $sum = $null
    try { $sum = Get-StatusSummary } catch { Write-Host "  Get-StatusSummary: $($_.Exception.Message)" }
    $t = @($sum.threats | Where-Object { $_.key -eq ('behavior:' + ('a' * 64)) })
    TCheck 'findings.json bulgusu tehditlerde' ($t.Count -eq 1) ''
    TCheck 'findings.json bulgusu kirmizilarda' (@($sum.reds | Where-Object { $_.key -like 'behavior:*' }).Count -eq 1) ''
    TCheck 'findings.json bulgusu alanlari' ($t.Count -eq 1 -and $t[0].title -eq 'Durdurulan program: kotu.exe' -and $t[0].report -eq 'Program: C:\x\kotu.exe' -and $t[0].path -eq 'C:\x\kotu.exe') ''
    [IO.File]::WriteAllText($fj, '[{"key": bozuk', (New-Object Text.UTF8Encoding($false)))
    $err = ''
    try { $sum = Get-StatusSummary } catch { $err = $_.Exception.Message }
    TCheck 'bozuk findings.json hata vermez' ($err -eq '') $err
    TCheck 'bozuk findings.json: bulgu yok' (@($sum.threats).Count -eq 0) ''
    Remove-Item $fj -Force
    $err = ''
    try { $sum = Get-StatusSummary } catch { $err = $_.Exception.Message }
    TCheck 'findings.json yok: hata yok' ($err -eq '' -and @($sum.threats).Count -eq 0) $err

    # Durum kontrolu metinleri
    $c1 = Get-GuardCheck @{ installed = $true; running = $true; sysmonOk = $true; preexisting = $false }
    $c2 = Get-GuardCheck @{ installed = $true; running = $true; sysmonOk = $true; preexisting = $true }
    $c3 = Get-GuardCheck @{ installed = $false; running = $false; sysmonOk = $false; preexisting = $false }
    TCheck 'bekci durumu: calisiyor ve Sysmon tamam -> tamam' ($c1.ok -eq $true) $c1.text
    TCheck 'bekci durumu: onceden kurulu Sysmon' ($c2.ok -eq $false -and $c2.text -eq 'Sysmon başka bir ayarla çalışıyor') $c2.text
    TCheck 'bekci durumu: hizmet yok -> uyari' ($c3.ok -eq $false) $c3.text
    $adv = @(Get-AdviceGroups @() $true)
    TCheck 'hizmet yok: "Davranis bekcisini acin" karti' (@($adv | Where-Object { $_.cat.title -eq 'Davranış bekçisini açın' }).Count -eq 1) ''
    $adv2 = @(Get-AdviceGroups @() $false)
    TCheck 'hizmet varsa kart yok' ($adv2.Count -eq 0) ''
    # Bekci veri klasoru varsayilani ProgramData\Cortmed (testte degistirildi)
    $src = Get-Content (Join-Path $RepoRoot 'windows\CortmedSecurity.ps1') -Raw -Encoding UTF8
    TCheck 'panel dugmesi Install-Guard.ps1 -Source ile calistirir' ($src -match "Install-Guard\.ps1" -and $src -match "'-Source'") ''
} catch {
    TCheck 'tepsi testleri calisti' $false $_.Exception.Message
} finally {
    Remove-Item $work -Recurse -Force -ErrorAction SilentlyContinue
}
exit $script:trayFails
