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
    # Cevap yazilamadi (false): pencere acik kalir, id cevaplanmamis
    $st2 = New-GuardState
    $m = Receive-GuardPrompt $st2 $json.Replace('"p1"', '"p4"') { param($id, $d) $false } -NoShow
    if ($m) { Click (Btn $m $killText) }
    TCheck 'cevap false: pencere acik kalir' ($m -and -not $m.IsDisposed -and $st2.open.ContainsKey('p4') -and -not $st2.answered.ContainsKey('p4')) ''
    # 10 dakika cevapsiz: id basina bir kez hatirlatma
    $now = Get-Date
    $due1 = @(Get-GuardOverdue $st2 $now.AddMinutes(5))
    $due2 = @(Get-GuardOverdue $st2 $now.AddMinutes(11))
    $due3 = @(Get-GuardOverdue $st2 $now.AddMinutes(20))
    TCheck '10 dakikadan once hatirlatma yok' ($due1.Count -eq 0) ($due1 -join ',')
    TCheck '10 dakika: cevapsiz id icin bir hatirlatma' (($due2 -join ',') -eq 'p4') ($due2 -join ',')
    TCheck 'hatirlatma id basina bir kez' ($due3.Count -eq 0) ($due3 -join ',')

    # Geri cekme / sonuc / bilinmeyen tur
    $notes = New-Object Collections.ArrayList
    $notify = { param($title, $text, $sticky) [void]$notes.Add("$sticky|$text") }
    $goneText = 'Bu program artık çalışmıyor; bir şey yapmanıza gerek yok.'
    $st3 = New-GuardState
    $w = Receive-GuardPrompt $st3 $json.Replace('"p1"', '"w1"') $answer -Notify $notify -Now $now -NoShow
    [void](Receive-GuardPrompt $st3 '{"type":"withdraw","id":"w1"}' $answer -Notify $notify -Now $now -NoShow)
    TCheck 'withdraw: pencere kapanir' ($w -and $w.IsDisposed -and -not $st3.open.ContainsKey('w1')) ''
    TCheck 'withdraw: acik pencere icin not' (($notes -join ',') -eq "False|$goneText") ($notes -join ',')
    TCheck 'withdraw: 10 dakika bildirimi yok' (@(Get-GuardOverdue $st3 $now.AddMinutes(11)).Count -eq 0) ''
    $notes.Clear()
    [void](Receive-GuardPrompt $st3 '{"type":"withdraw","id":"yok"}' $answer -Notify $notify -Now $now -NoShow)
    TCheck 'withdraw: pencere yoksa not yok' ($notes.Count -eq 0) ($notes -join ',')
    $r1 = Receive-GuardPrompt $st3 $json.Replace('"p1"', '"r1"') $answer -Notify $notify -Now $now -NoShow
    [void](Receive-GuardPrompt $st3 '{"type":"result","id":"r1","ok":false}' $answer -Notify $notify -Now $now -NoShow)
    TCheck 'result ok=false: pencere kapanir ve not' ($r1 -and $r1.IsDisposed -and ($notes -join ',') -eq "False|$goneText") ($notes -join ',')
    $calls.Clear(); $notes.Clear()
    $r2 = Receive-GuardPrompt $st3 $json.Replace('"p1"', '"r2"') $answer -Notify $notify -Now $now -NoShow
    if ($r2) { Click (Btn $r2 $allowText) }
    [void](Receive-GuardPrompt $st3 '{"type":"result","id":"r2","ok":true}' $answer -Notify $notify -Now $now -NoShow)
    TCheck 'result ok=true: not yok, hatirlatma yok' ($notes.Count -eq 0 -and @(Get-GuardOverdue $st3 $now.AddMinutes(11)).Count -eq 0) ($notes -join ',')
    # Cevap yolda kayboldu: soru yeniden gelir, saklanan karar yeniden gonderilir, pencere acilmaz
    $calls.Clear()
    $again = Receive-GuardPrompt $st3 $json.Replace('"p1"', '"r2"') $answer -Notify $notify -Now $now -NoShow
    TCheck 'cevaplanan soru yeniden gelince karar yeniden gonderilir' ($again -eq $null -and ($calls -join ',') -eq 'r2|allow') ($calls -join ',')
    $calls.Clear()
    $u = Receive-GuardPrompt $st3 '{"type":"baska","id":"u1","program":"a.exe"}' $answer -Notify $notify -Now $now -NoShow
    TCheck 'bilinmeyen tur yok sayilir' ($u -eq $null -and -not $st3.open.ContainsKey('u1') -and $calls.Count -eq 0) ''
    $nt = Receive-GuardPrompt $st3 '{"id":"u2","program":"a.exe"}' $answer -Notify $notify -Now $now -NoShow
    TCheck 'turu olmayan satir yok sayilir' ($nt -eq $null) ''

    # Kapat + result ok=true: otomatik karantina ayari aciksa sorunun dosyasi mevcut Invoke-Quarantine ile karantinaya
    $qcalls = New-Object Collections.ArrayList
    $fakeQ = { param($path) [void]$qcalls.Add($path); $true }
    $st6 = New-GuardState
    $k1 = Receive-GuardPrompt $st6 $json.Replace('"p1"', '"k1"') $answer -Notify $notify -Now $now -NoShow -Quarantine $fakeQ
    if ($k1) { Click (Btn $k1 $killText) }
    TCheck 'kapat: sonuc gelmeden karantina yok' ($qcalls.Count -eq 0) ($qcalls -join ',')
    [void](Receive-GuardPrompt $st6 '{"type":"result","id":"k1","ok":true}' $answer -Notify $notify -Now $now -NoShow -Quarantine $fakeQ)
    TCheck 'kapat + ok=true: sorunun yolu karantinaya verilir' (($qcalls -join ',') -eq 'C:\Users\x\Downloads\kotu.exe') ($qcalls -join ',')
    [void](Receive-GuardPrompt $st6 '{"type":"result","id":"k1","ok":true}' $answer -Notify $notify -Now $now -NoShow -Quarantine $fakeQ)
    TCheck 'ikinci ok=true: yeniden karantina yok' ($qcalls.Count -eq 1) ($qcalls -join ',')
    $k2 = Receive-GuardPrompt $st6 $json.Replace('"p1"', '"k2"') $answer -Notify $notify -Now $now -NoShow -Quarantine $fakeQ
    if ($k2) { Click (Btn $k2 $allowText) }
    [void](Receive-GuardPrompt $st6 '{"type":"result","id":"k2","ok":true}' $answer -Notify $notify -Now $now -NoShow -Quarantine $fakeQ)
    $k3 = Receive-GuardPrompt $st6 $json.Replace('"p1"', '"k3"') $answer -Notify $notify -Now $now -NoShow -Quarantine $fakeQ
    if ($k3) { Click (Btn $k3 $killText) }
    [void](Receive-GuardPrompt $st6 '{"type":"result","id":"k3","ok":false}' $answer -Notify $notify -Now $now -NoShow -Quarantine $fakeQ)
    TCheck 'izin ya da ok=false: karantina yok' ($qcalls.Count -eq 1) ($qcalls -join ',')

    # Varsayilan karantina: ayara bagli, mevcut Invoke-Quarantine (calisma kopyasinin Karantina klasoru)
    $victim = Join-Path $work 'indirilen.exe'
    [IO.File]::WriteAllBytes($victim, [byte[]](77, 90))
    $kjson = '{"type":"ask","id":"q1","program":"indirilen.exe","path":' + (ConvertTo-Json $victim) + ',"publisher":"","score":90,"reasons":["r"]}'
    $st7 = New-GuardState
    $q1 = Receive-GuardPrompt $st7 $kjson $answer -Notify $notify -Now $now -NoShow
    if ($q1) { Click (Btn $q1 $killText) }
    [void](Receive-GuardPrompt $st7 '{"type":"result","id":"q1","ok":true}' $answer -Notify $notify -Now $now -NoShow)
    TCheck 'otomatik karantina kapaliyken dosyaya dokunulmaz' (Test-Path $victim) ''
    $cfg = Get-Config; $cfg.autoQuarantine = $true; Save-Config $cfg
    $q2 = Receive-GuardPrompt $st7 $kjson.Replace('"q1"', '"q2"') $answer -Notify $notify -Now $now -NoShow
    if ($q2) { Click (Btn $q2 $killText) }
    [void](Receive-GuardPrompt $st7 '{"type":"result","id":"q2","ok":true}' $answer -Notify $notify -Now $now -NoShow)
    TCheck 'otomatik karantina acikken dosya Karantina klasorune tasinir' ((-not (Test-Path $victim)) -and
        @(Get-ChildItem (Join-Path $work 'Karantina') -Filter '*indirilen.exe.karantina').Count -eq 1) ''
    $cfg.autoQuarantine = $false; Save-Config $cfg

    # Zamanlayici tiki: sahte istemci ve saat (gercek bekleme yok)
    $fake = New-Object psobject -Property @{ Connected = $false; Q = (New-Object Collections.Queue) }
    $fake | Add-Member ScriptMethod TryDequeuePrompt { param([ref]$j) if ($this.Q.Count -gt 0) { $j.Value = $this.Q.Dequeue(); return $true }; return $false }
    $st4 = New-GuardState
    $t0 = Get-Date '2026-10-29T10:00:00'
    $notes.Clear()
    $fake.Connected = $true
    $fake.Q.Enqueue($json.Replace('"p1"', '"a1"')); $fake.Q.Enqueue($json.Replace('"p1"', '"a2"'))
    Invoke-GuardTick $st4 $fake $t0 $answer $notify -NoShow
    TCheck 'tik: sorular kuyruktan alinir' ($st4.open.ContainsKey('a1') -and $st4.open.ContainsKey('a2')) ''
    # Baglanti koptu ve yeniden kuruldu; hizmet yalnizca a1'i yeniden gonderdi
    $fake.Connected = $false
    Invoke-GuardTick $st4 $fake $t0.AddSeconds(10) $answer $notify -NoShow
    $fake.Connected = $true
    $fake.Q.Enqueue($json.Replace('"p1"', '"a1"'))
    Invoke-GuardTick $st4 $fake $t0.AddSeconds(11) $answer $notify -NoShow
    Invoke-GuardTick $st4 $fake $t0.AddSeconds(14) $answer $notify -NoShow
    TCheck 'yeniden baglanti: 5 sn dolmadan kapatma yok' ($st4.open.ContainsKey('a2')) ''
    Invoke-GuardTick $st4 $fake $t0.AddSeconds(17) $answer $notify -NoShow
    TCheck 'yeniden baglanti: yeniden gonderilmeyen soru kapanir' (-not $st4.open.ContainsKey('a2') -and $st4.gone.ContainsKey('a2')) ''
    TCheck 'yeniden baglanti: yeniden gonderilen soru acik kalir' ($st4.open.ContainsKey('a1') -and -not $st4.gone.ContainsKey('a1')) ''
    $notes.Clear()
    Invoke-GuardTick $st4 $fake $t0.AddMinutes(11) $answer $notify -NoShow
    $sticky = @($notes | Where-Object { $_ -like 'True|*' })
    TCheck 'yeniden baglanti: kapanan soru icin 10 dakika bildirimi yok' ($sticky.Count -eq 1 -and $sticky[0] -like '*kotu.exe*') ($notes -join ' / ')
    # 10 dakika: kapatilmis pencere bir kez yeniden acilir
    $st4.open['a1'].Close()
    $st5 = New-GuardState
    $fake.Q.Enqueue($json.Replace('"p1"', '"b1"'))
    Invoke-GuardTick $st5 $fake $t0 $answer $notify -NoShow
    $st5.open['b1'].Close()
    $notes.Clear()
    Invoke-GuardTick $st5 $fake $t0.AddMinutes(11) $answer $notify -NoShow
    $reopened = $st5.open['b1']
    TCheck '10 dakika: kapatilan pencere yeniden acilir' ($reopened -and -not $reopened.IsDisposed -and $notes.Count -eq 1) ($notes -join ' / ')
    Invoke-GuardTick $st5 $fake $t0.AddMinutes(12) $answer $notify -NoShow
    TCheck '10 dakika: bildirim bir kez' ($notes.Count -eq 1) ($notes -join ' / ')

    # 4) findings.json davranis bulgulari gecmis kayit: Onerilerimiz'de "Durdurulan programlar", tehdit degil
    $fj = Join-Path $GuardDataDir 'findings.json'
    $finding = '[{"key":"behavior:' + ('a' * 64) + '","level":"RED","title":"Durdurulan program: kotu.exe","detail":"Belgelerinizi hızla değiştiriyor","path":"C:\\x\\kotu.exe","tab":"threat","report":"Program: C:\\x\\kotu.exe","time":"2026-10-29T08:30:00.0000000Z"},' +
        '{"key":"behavior:' + ('b' * 64) + '","level":"YELLOW","title":"Şüpheli davranış: b.exe","detail":"x","path":"C:\\x\\b.exe","tab":"threat","report":"r"}]'
    [IO.File]::WriteAllText($fj, $finding, (New-Object Text.UTF8Encoding($false)))
    $sum = $null
    try { $sum = Get-StatusSummary } catch { Write-Host "  Get-StatusSummary: $($_.Exception.Message)" }
    $t = @($sum.advice | Where-Object { $_.key -eq ('behavior:' + ('a' * 64)) })
    TCheck 'davranis bulgusu Onerilerimiz''de' ($t.Count -eq 1) ''
    TCheck 'davranis bulgusu tehdit sayilmaz' (@($sum.threats | Where-Object { $_.key -like 'behavior:*' }).Count -eq 0) ''
    TCheck 'davranis bulgusu kirmizi sayilmaz' (@($sum.reds).Count -eq 0) ''
    TCheck 'davranis bulgusu sari, ozgun seviye saklanir' ($t.Count -eq 1 -and $t[0].level -eq 'YELLOW' -and $t[0].guardLevel -eq 'RED') ''
    TCheck 'davranis bulgusu alanlari' ($t.Count -eq 1 -and $t[0].title -eq 'Durdurulan program: kotu.exe' -and $t[0].report -eq 'Program: C:\x\kotu.exe' -and $t[0].path -eq 'C:\x\kotu.exe') ''
    TCheck 'davranis bulgusu tarihi gosterilir' ($t.Count -eq 1 -and $t[0].detail -like '29.10.2026 *Belgelerinizi*') $t[0].detail
    $groups = @(Get-AdviceGroups $sum.advice)
    $grp = @($groups | Where-Object { $_.cat.title -eq 'Durdurulan programlar' })
    TCheck '"Durdurulan programlar" yalnizca kapatilan (RED) bulguyla' ($grp.Count -eq 1 -and @($grp[0].items).Count -eq 1 -and
        $grp[0].items[0].guardLevel -eq 'RED') ''
    $redText = 'Cortmed bu programları durdurdu ve sizin onayınızla kapattı. Dosyaları hâlâ bilgisayarınızda; tanımıyorsanız listeden açıp ''Karantinaya al'' ile kaldırın.'
    TCheck '"Durdurulan programlar" aciklamasi hicbir sey kalmadi demez' ($grp.Count -eq 1 -and $grp[0].cat.text -eq $redText) $grp[0].cat.text
    $wgrp = @($groups | Where-Object { $_.cat.title -eq 'Şüpheli davranan programlar' })
    TCheck '"Supheli davranan programlar" yalnizca durdurulmayan (YELLOW) bulguyla' ($wgrp.Count -eq 1 -and @($wgrp[0].items).Count -eq 1 -and
        $wgrp[0].items[0].guardLevel -eq 'YELLOW' -and $wgrp[0].items[0].title -eq 'Şüpheli davranış: b.exe') ''
    $warnText = 'Bu programlar şüpheli bir şey yaptı ama durdurulmadı. Tanımıyorsanız listeden açıp ''Karantinaya al'' ile kaldırın.'
    TCheck '"Supheli davranan programlar" durust aciklama' ($wgrp.Count -eq 1 -and $wgrp[0].cat.text -eq $warnText) $wgrp[0].cat.text
    TCheck 'Warn bulgusu sari kalir' ($wgrp.Count -eq 1 -and $wgrp[0].items[0].level -eq 'YELLOW') ''

    # Ayrintilar penceresi: davranis bulgusu icin "Karantinaya al" (dosya varsa); dosya bulgusu icin yok
    $qf = Join-Path $work 'supheli.exe'
    [IO.File]::WriteAllBytes($qf, [byte[]](77, 90))
    $rf = New-ReportForm ([pscustomobject]@{ key = 'behavior:x'; level = 'YELLOW'; title = 't'; detail = 'd'; path = $qf; report = 'r' })
    $rbtns = @(All-Controls $rf | Where-Object { $_ -is [Windows.Forms.Button] } | ForEach-Object Text)
    TCheck 'ayrintilar: davranis bulgusunda Karantinaya al' ($rbtns -contains 'Karantinaya al') ($rbtns -join ' / ')
    TCheck 'ayrintilar penceresi gosterilmedi' (-not $rf.Visible) ''
    $rf.Dispose()
    $rf2 = New-ReportForm ([pscustomobject]@{ key = 'behavior:y'; level = 'YELLOW'; title = 't'; detail = 'd'; path = (Join-Path $work 'yok.exe'); report = 'r' })
    TCheck 'ayrintilar: dosya yoksa Karantinaya al yok' (@(All-Controls $rf2 | Where-Object { $_ -is [Windows.Forms.Button] -and $_.Text -eq 'Karantinaya al' }).Count -eq 0) ''
    $rf2.Dispose()
    # Windows klasoru ve Program Files altindaki dosyalar: Karantinaya al yok (dosya var olsa bile)
    $sysFile = Join-Path ([Environment]::SystemDirectory) 'svchost.exe'
    $rf3 = New-ReportForm ([pscustomobject]@{ key = 'behavior:z'; level = 'YELLOW'; title = 't'; detail = 'd'; path = $sysFile; report = 'r' })
    TCheck 'ayrintilar: Windows klasorundeki dosyada Karantinaya al yok' (@(All-Controls $rf3 | Where-Object { $_ -is [Windows.Forms.Button] -and $_.Text -eq 'Karantinaya al' }).Count -eq 0) ''
    $rf3.Dispose()
    TCheck 'sistem yolu: Windows ve Program Files' ((Test-GuardSystemPath $sysFile) -and
        (Test-GuardSystemPath (Join-Path ([Environment]::GetFolderPath('ProgramFiles')) 'x\y.exe')) -and
        (Test-GuardSystemPath (Join-Path ([Environment]::GetFolderPath('ProgramFilesX86')) 'x\y.exe')) -and
        -not (Test-GuardSystemPath $qf) -and -not (Test-GuardSystemPath ([Environment]::GetFolderPath('Windows') + 'x\a.exe'))) ''
    # Otomatik karantina sistem yollarini atlar (gercek Invoke-Quarantine yerine sahte: sistem dosyasina asla dokunulmaz)
    $realQ = ${function:Invoke-Quarantine}
    $sysQ = New-Object Collections.ArrayList
    ${function:Invoke-Quarantine} = { param($file) [void]$sysQ.Add($file); $true }
    if ((Get-Command Invoke-Quarantine).ScriptBlock.ToString() -notmatch 'sysQ') { throw 'sahte Invoke-Quarantine yuklenemedi; sistem dosyasi denenmez' }
    $qcfg = Get-Config; $qcfg.autoQuarantine = $true; Save-Config $qcfg
    $rq1 = & $DefaultGuardQuarantine $sysFile
    $rq2 = & $DefaultGuardQuarantine $qf
    $qcfg.autoQuarantine = $false; Save-Config $qcfg
    ${function:Invoke-Quarantine} = $realQ
    TCheck 'otomatik karantina Windows klasorunu atlar' (-not $rq1 -and -not ($sysQ -contains $sysFile)) ($sysQ -join ',')
    TCheck 'otomatik karantina kullanici dosyasini alir' ($rq2 -and ($sysQ -contains $qf)) ($sysQ -join ',')
    $qsrc = Get-Content (Join-Path $RepoRoot 'windows\CortmedSecurity.ps1') -Raw -Encoding UTF8
    TCheck 'Karantinaya al mevcut Invoke-Quarantine''i kullanir' (@([regex]::Matches($qsrc, 'function Invoke-Quarantine')).Count -eq 1 -and
        $qsrc -match "'Karantinaya al'[\s\S]{0,800}Invoke-Quarantine") ''

    # Yeni Warn anahtari basina bir kisa (kalici olmayan) bildirim; gosterilenler tepsinin veri klasorunde
    $wn = New-Object Collections.ArrayList
    $wnotify = { param($title, $text, $sticky) [void]$wn.Add("$sticky|$text") }
    $c1 = Invoke-GuardWarnNotices $wnotify
    TCheck 'Warn bildirimi: yeni anahtar icin bir kez, kalici degil' ($wn.Count -eq 1 -and $wn[0] -like 'False|*b.exe*') ($wn -join ' / ')
    TCheck 'Warn bildirimi: kapatilan (RED) bulgu icin yok' (-not ($wn -join ' ').Contains('kotu.exe')) ($wn -join ' / ')
    [void](Invoke-GuardWarnNotices $wnotify)
    TCheck 'Warn bildirimi: ayni anahtar ikinci kez yok' ($wn.Count -eq 1) ($wn -join ' / ')
    TCheck 'Warn bildirimi: gosterilenler data klasorunde' ((Test-Path (Join-Path $work 'data\guard-warn-shown.txt')) -and
        (Get-Content (Join-Path $work 'data\guard-warn-shown.txt') -Raw).Contains('behavior:' + ('b' * 64))) ''
    $finding2 = $finding.TrimEnd(']') + ',{"key":"behavior:' + ('c' * 64) + '","level":"YELLOW","title":"Şüpheli davranış: c.exe","detail":"x","path":"C:\\x\\c.exe","tab":"threat","report":"r"}]'
    [IO.File]::WriteAllText($fj, $finding2, (New-Object Text.UTF8Encoding($false)))
    [void](Invoke-GuardWarnNotices $wnotify)
    TCheck 'Warn bildirimi: yeni ikinci anahtar bir kez' ($wn.Count -eq 2 -and $wn[1] -like '*c.exe*') ($wn -join ' / ')
    [IO.File]::WriteAllText($fj, '[{"key": bozuk', (New-Object Text.UTF8Encoding($false)))
    $err = ''
    try { $sum = Get-StatusSummary } catch { $err = $_.Exception.Message }
    TCheck 'bozuk findings.json hata vermez' ($err -eq '') $err
    TCheck 'bozuk findings.json: bulgu yok' (@($sum.threats).Count -eq 0 -and @($sum.advice).Count -eq 0) ''
    Remove-Item $fj -Force
    $err = ''
    try { $sum = Get-StatusSummary } catch { $err = $_.Exception.Message }
    TCheck 'findings.json yok: hata yok' ($err -eq '' -and @($sum.threats).Count -eq 0) $err

    # Durum kontrolu metinleri
    $c1 = Get-GuardCheck @{ installed = $true; running = $true; sysmonOk = $true; preexisting = $false }
    $c2 = Get-GuardCheck @{ installed = $true; running = $true; sysmonOk = $true; preexisting = $true }
    $c3 = Get-GuardCheck @{ installed = $false; running = $false; sysmonOk = $false; preexisting = $false }
    $c4 = Get-GuardCheck @{ installed = $true; running = $false; sysmonOk = $false; preexisting = $false }
    TCheck 'bekci durumu: calisiyor ve Sysmon tamam -> tamam' ($c1.ok -eq $true -and -not $c1.offer) $c1.text
    TCheck 'bekci durumu: onceden kurulu Sysmon' ($c2.ok -eq $false -and $c2.text -eq 'Sysmon başka bir ayarla çalışıyor') $c2.text
    TCheck 'bekci durumu: hizmet yok -> uyari ve kart' ($c3.ok -eq $false -and $c3.offer) $c3.text
    TCheck 'bekci durumu: calismiyor -> ne yapilacagi ve kart' ($c4.offer -and $c4.text -eq 'Davranış bekçisi çalışmıyor' -and
        $c4.hint.Contains('Bilgisayarı yeniden başlatın; düzelmezse ''Davranış bekçisini açın'' ile yeniden kurun.')) $c4.hint
    $adv = @(Get-AdviceGroups @() $true)
    TCheck 'hizmet yok: "Davranis bekcisini acin" karti' (@($adv | Where-Object { $_.cat.title -eq 'Davranış bekçisini açın' }).Count -eq 1) ''
    $advRun = @(Get-AdviceGroups @() ([bool]$c4.offer) ([string]$c4.hint))
    TCheck 'calismiyor: kart ne yapilacagini soyler' ($advRun.Count -eq 1 -and $advRun[0].cat.text -eq $c4.hint -and $GuardAdvice.text -ne $c4.hint) ''
    $adv2 = @(Get-AdviceGroups @() $false)
    TCheck 'hizmet varsa kart yok' ($adv2.Count -eq 0) ''
    TCheck 'kurulum notu: 0 -> yok' ($null -eq (Get-GuardSetupNote 0)) ''
    TCheck 'kurulum notu: 2 -> Sysmon' ((Get-GuardSetupNote 2) -eq 'Davranış bekçisi kuruldu ama Sysmon kurulamadı; bazı davranışlar görülmeyebilir.') ''
    TCheck 'kurulum notu: 1 -> kurulamadi' ((Get-GuardSetupNote 1) -eq 'Davranış bekçisi kurulamadı. Bilgisayarı yeniden başlatıp tekrar deneyin.') ''
    # Bekci veri klasoru varsayilani ProgramData\Cortmed (testte degistirildi)
    $src = Get-Content (Join-Path $RepoRoot 'windows\CortmedSecurity.ps1') -Raw -Encoding UTF8
    TCheck 'panel dugmesi Install-Guard.ps1 -Source ile calistirir' ($src -match "Install-Guard\.ps1" -and $src -match "'-Source'") ''

    # Onarim (hizmet var): yalnizca Program Files\Cortmed'deki yonetici kopyasi; ilk kurulum: paket kopyasi ($Root)
    $pfFake = Join-Path $work 'pf'
    New-Item -ItemType Directory -Force (Join-Path $pfFake 'Cortmed') | Out-Null
    'x' | Set-Content (Join-Path $work 'Install-Guard.ps1')
    $fresh = Get-GuardSetupCommand $false $pfFake
    TCheck 'ilk kurulum: paket kopyasi' ($fresh.script -eq (Join-Path $work 'Install-Guard.ps1') -and $fresh.source -eq $work) "$($fresh.script) | $($fresh.source)"
    $none = Get-GuardSetupCommand $true $pfFake
    TCheck 'onarim: Program Files kopyasi yoksa kullanici kopyasi YUKSELTILMEZ' ($null -eq $none.script -and $none.missing) "$($none.script)"
    'x' | Set-Content (Join-Path $pfFake 'Cortmed\Install-Guard.ps1')
    $rep = Get-GuardSetupCommand $true $pfFake
    TCheck 'onarim: Program Files\Cortmed\Install-Guard.ps1 -Source Program Files\Cortmed' ($rep.script -eq (Join-Path $pfFake 'Cortmed\Install-Guard.ps1') -and
        $rep.source -eq (Join-Path $pfFake 'Cortmed')) "$($rep.script) | $($rep.source)"
    $pfReal = Get-ProgramFilesDir
    TCheck 'Program Files ortam degiskeni olmadan bulunur' ($pfReal -and (Test-Path $pfReal) -and $pfReal -notmatch 'x86') $pfReal
    TCheck 'Get-ProgramFilesDir ortam degiskeni kullanmaz' ((Get-Command Get-ProgramFilesDir).Definition -notmatch '\$env:') ''

    # Ayarlar penceresi: 7 bolum, Kaydet/Vazgec yok, tek Kapat
    $sf = $null
    try { $sf = New-SettingsForm } catch { Write-Host "  New-SettingsForm: $($_.Exception.Message)" }
    TCheck 'ayarlar penceresi kuruldu' ($sf -ne $null)
    if ($sf) {
        $navNames = @($sf.Tag.nav.Keys)
        $want = @('Koruma', 'Davranış bekçisi', 'Veritabanı', 'Güvenilir dosyalar', 'Karantina', 'Gelişmiş', 'Hakkında')
        TCheck 'ayarlar: 7 gezinme bolumu' ($navNames.Count -eq 7 -and (($navNames -join '|') -eq ($want -join '|'))) ($navNames -join '|')
        TCheck 'ayarlar: 7 sayfa' ($sf.Tag.pages.Count -eq 7) ''
        foreach ($n in $want) { Select-SettingsPage $sf.Tag $n }
        TCheck 'ayarlar: tum sayfalar acilir' $true ''
        TCheck 'ayarlar: Kapat var, Kaydet / Vazgec yok' ((Btn $sf 'Kapat') -and -not (Btn $sf 'Kaydet') -and -not (Btn $sf 'Vazgeç')) ''
        $sf.Dispose()
    }

    # Sessiz mod: sari / bilgi bildirimi gizlenir, kirmizi (Sticky) her zaman gosterilir
    $quiet = [pscustomobject]@{ quietMode = $true }
    $loud = [pscustomobject]@{ quietMode = $false }
    TCheck 'sessiz mod: sari bildirim gizlenir' (-not (Test-ToastAllowed $false $quiet)) ''
    TCheck 'sessiz mod: kirmizi bildirim yine gosterilir' (Test-ToastAllowed $true $quiet) ''
    TCheck 'sessiz mod kapali: sari bildirim gosterilir' (Test-ToastAllowed $false $loud) ''
    TCheck 'quietMode varsayilani kapali' ((Get-Config).quietMode -eq $false) ''
    # Tarayici korumasi: son gorulme dosyasi 7 gunden tazeyse yesil, aksi halde Onerilerimiz karti (kalkani sarartmaz)
    $bd = Join-Path $work 'browserdata'
    New-Item -ItemType Directory -Force $bd | Out-Null
    $seenFile = Join-Path $bd 'browser-lastseen.txt'
    $nowU = (Get-Date).ToUniversalTime()
    $bcNone = Get-BrowserCheck $bd
    TCheck 'tarayici: dosya yok -> kapali, oneri sunulur' ((-not $bcNone.ok) -and $bcNone.offer) ''
    [IO.File]::WriteAllText($seenFile, $nowU.ToString('o'))
    $bcFresh = Get-BrowserCheck $bd
    TCheck 'tarayici: taze dosya -> Tarayici korumasi acik' ($bcFresh.ok -and $bcFresh.text -eq 'Tarayıcı koruması açık' -and -not $bcFresh.offer) "$($bcFresh.text)"
    [IO.File]::WriteAllText($seenFile, $nowU.AddDays(-8).ToString('o'))
    $bcOld = Get-BrowserCheck $bd
    TCheck 'tarayici: 8 gunluk dosya -> oneri sunulur' ((-not $bcOld.ok) -and $bcOld.offer) ''
    [IO.File]::WriteAllText($seenFile, $nowU.AddDays(-6).ToString('o'))
    TCheck 'tarayici: 6 gunluk dosya -> acik' ((Get-BrowserCheck $bd).ok) ''
    [IO.File]::WriteAllText($seenFile, 'bozuk tarih')
    TCheck 'tarayici: bozuk dosya -> oneri sunulur' (-not (Get-BrowserCheck $bd).ok) ''
    [IO.File]::WriteAllText($seenFile, $nowU.AddDays(2).ToString('o'))
    TCheck 'tarayici: gelecekteki tarih -> oneri sunulur' (-not (Get-BrowserCheck $bd).ok) ''

    $gOff = @(Get-AdviceGroups @() $false '' $true)
    $gBrowser = @($gOff | Where-Object { $_.cat.title -eq 'Tarayıcı korumasını ekleyin' })
    TCheck 'oneri karti: Tarayici korumasini ekleyin' ($gBrowser.Count -eq 1 -and $gBrowser[0].cat.button -eq 'Nasıl eklenir?' -and
        $gBrowser[0].cat.text -eq 'Şifre tekrarı, sızmış şifre ve indirme kontrolü için tarayıcınıza Cortmed eklentisini ekleyin.') ''
    TCheck 'oneri karti: tarayici acikken yok' (@(Get-AdviceGroups @() $false '' $false).Count -eq 0) ''
    $gOrder = @(Get-AdviceGroups @() $true '' $true)
    TCheck 'oneri karti: bekci karti once, tarayici sonra' ($gOrder.Count -eq 2 -and $gOrder[0].cat.id -eq 'guard' -and $gOrder[1].cat.id -eq 'browser') ''
    $card = New-AdviceCard $gBrowser[0] 600 (New-Object Windows.Forms.ToolTip) { param($g) }
    $cardTexts = @(All-Controls $card | ForEach-Object Text)
    TCheck 'oneri karti kurulur, dugmesi var' ($card -and $cardTexts -contains 'Nasıl eklenir?' -and $cardTexts -contains 'Tarayıcı korumasını ekleyin') ($cardTexts -join '|')

    # Rehber penceresi
    $gf = $null
    try { $gf = New-BrowserGuideForm } catch { Write-Host "  New-BrowserGuideForm: $($_.Exception.Message)" }
    TCheck 'rehber penceresi kuruldu' ($gf -ne $null)
    if ($gf) {
        $folder = Join-Path $env:LOCALAPPDATA 'CortmedSecurity\browser'
        TCheck 'rehber basligi' ($gf.Text -eq 'Tarayıcı korumasını ekleyin') $gf.Text
        TCheck 'rehber gosterilmedi' (-not $gf.Visible) ''
        $gbtn = @(All-Controls $gf | Where-Object { $_ -is [Windows.Forms.Button] } | ForEach-Object Text)
        TCheck 'rehber: Chrome / Edge dugmeleri' ($gbtn -contains 'Chrome' -and $gbtn -contains 'Edge') ($gbtn -join '|')
        TCheck 'rehber: Tarayiciyi ac dugmesi' ($gbtn -contains 'Tarayıcıyı aç') ($gbtn -join '|')
        foreach ($b in 'Chrome', 'Edge') {
            Set-BrowserGuideBrowser $gf $b
            $gt = @(All-Controls $gf | ForEach-Object Text)
            $addr = if ($b -eq 'Chrome') { 'chrome://extensions' } else { 'edge://extensions' }
            $s3 = if ($b -eq 'Chrome') { 'Paketlenmemiş öğe yükle düğmesine basın.' } else { 'Paketten çıkarılmışı yükle düğmesine basın.' }
            $s2 = if ($b -eq 'Chrome') { 'Sağ üstteki Geliştirici modu düğmesini açın.' } else { 'Sol alttaki Geliştirici modu düğmesini açın.' }
            TCheck "rehber $b : adres" ($gt -contains $addr) ($gt -join '|')
            $s4 = 'Açılan pencerede üstteki adres çubuğuna kopyaladığınız yolu yapıştırın, Enter''a basın, sonra Klasör seç düğmesine basın.'
            TCheck "rehber $b : 4 adim metni" (($gt -contains 'Tarayıcınızda şu adresi açın:') -and ($gt -contains $s2) -and ($gt -contains $s3) -and ($gt -contains $s4)) ($gt -join '|')
            # Gizli %LOCALAPPDATA% icin yol yapistirilir: uzun 4. adim metni klasor yolunun ustune binmez
            $l4 = @(All-Controls $gf | Where-Object { $_.Text -eq $s4 })[0]
            $lp = @(All-Controls $gf | Where-Object { $_ -is [Windows.Forms.Label] -and $_.Text -eq $folder })[0]
            TCheck "rehber $b : 4. adim yolun ustune binmez" ($l4 -and $lp -and ($l4.Top + $l4.PreferredHeight) -le $lp.Top -and ($lp.Top + $lp.PreferredHeight) -le $gf.Tag.steps.Height) "$($l4.Top)+$($l4.PreferredHeight) / $($lp.Top)"
            TCheck "rehber $b : genisletilmis klasor yolu" ($gt -contains $folder -and $folder -notmatch '%') $folder
            TCheck "rehber $b : Kopyala dugmeleri" ((@(All-Controls $gf | Where-Object { $_ -is [Windows.Forms.Button] -and $_.Text -eq 'Kopyala' }).Count -eq 1) -and
                (Btn $gf 'Klasör yolunu kopyala')) ''
            TCheck "rehber $b : numaralar 1-4" (($gt -contains '1') -and ($gt -contains '2') -and ($gt -contains '3') -and ($gt -contains '4')) ''
            TCheck "rehber $b : not" ($gt -contains 'Eklenti şifrelerinizi bilgisayarınızdan dışarı göndermez.') ''
        }
        $other = if ($gf.Tag.browser -eq 'Edge') { 'chrome://extensions' } else { 'edge://extensions' }
        TCheck 'rehber: secili olmayan tarayicinin adresi gorunmez' (@(All-Controls $gf | ForEach-Object Text) -notcontains $other) ''
        $gf.Dispose()
    }
    # Tarayiciyi ac: yalnizca standart kurulum yollari, PATH'e guvenmez
    $bp = Get-BrowserExePath 'Chrome'
    TCheck 'tarayici yolu: standart klasorlerden biri ya da bos' ((-not $bp) -or ($bp -match '\\(Google\\Chrome\\Application\\chrome\.exe)$' -and (Test-Path $bp))) "$bp"
    TCheck 'tarayici yolu: Edge' ((-not (Get-BrowserExePath 'Edge')) -or ((Get-BrowserExePath 'Edge') -match 'msedge\.exe$')) ''
    TCheck 'Get-BrowserExePath PATH kullanmaz' ((Get-Command Get-BrowserExePath).Definition -notmatch 'Get-Command|\$env:PATH|\.Path\b') ''

    # "Beni oraya goturun" dugmeleri: sabit izinli liste, hicbir sey gercekten acilmaz
    $sysDir = [Environment]::SystemDirectory
    $map = @(
        @('defender-off', 'Virüs korumasını aç', 'uri', 'windowsdefender://threatsettings'),
        @('defender-extra', 'Virüs korumasını aç', 'uri', 'windowsdefender://threatsettings'),
        @('defender-old', 'Güncellemeleri denetle', 'uri', 'windowsdefender://threat'),
        @('firewall', 'Güvenlik duvarını aç', 'uri', 'windowsdefender://network'),
        @('smartscreen', 'İndirme uyarılarını aç', 'uri', 'windowsdefender://appbrowser'),
        @('uac', 'İzin penceresi ayarını aç', 'exe', (Join-Path $sysDir 'UserAccountControlSettings.exe')),
        @('admin', 'Hesap ayarlarını aç', 'uri', 'ms-settings:otherusers'),
        @('dns', 'Ağ ayarlarını aç', 'uri', 'ms-settings:network-status'),
        @('updates', 'Windows Update''i aç', 'uri', 'ms-settings:windowsupdate'),
        @('persist-script:x', 'Başlangıç uygulamalarını aç', 'uri', 'ms-settings:startupapps'),
        @('persist-unsigned:C:\x.exe', 'Başlangıç uygulamalarını aç', 'uri', 'ms-settings:startupapps'),
        @('startup-script:a.vbs', 'Başlangıç uygulamalarını aç', 'uri', 'ms-settings:startupapps')
    )
    foreach ($m in $map) {
        $a = Get-FindingAction (New-Finding $m[0] 'YELLOW' 't' 'd')
        TCheck "eylem: $($m[0])" ($a -and $a.label -eq $m[1] -and $a.kind -eq $m[2] -and $a.target -eq $m[3]) ($a | Out-String)
    }
    $tf = New-Finding 'persist-unsigned:T' 'YELLOW' 't' 'd'
    $tf | Add-Member -NotePropertyName source -NotePropertyValue 'Zamanlanmış görev'
    $ta = Get-FindingAction $tf
    TCheck 'eylem: zamanlanmis gorev mmc ile taskschd.msc' ($ta -and $ta.kind -eq 'exe' -and $ta.target -eq (Join-Path $sysDir 'mmc.exe') -and $ta.args -eq ('"{0}"' -f (Join-Path $sysDir 'taskschd.msc'))) ($ta | Out-String)
    TCheck 'eylem: bilinmeyen anahtar -> null' ($null -eq (Get-FindingAction (New-Finding 'nope' 'YELLOW' 't' 'd'))) ''
    TCheck 'eylem: guard onerisi kartlarina dokunulmaz' ($null -eq (Get-FindingAction (New-Finding 'guard-missing' 'YELLOW' 't' 'd'))) ''
    TCheck 'eylem: bulgu metni adrese donusmez' ($null -eq (Get-FindingAction (New-Finding 'x' 'YELLOW' 'windowsdefender://threat' 'ms-settings:network-status'))) ''

    $victim = Join-Path $work 'sahte.exe'
    Set-Content -Path $victim -Value 'x'
    $sa = Get-FindingAction (New-Finding "file:abc" 'RED' 't' 'd' $victim)
    TCheck 'eylem: dosya bulgusu -> select' ($sa -and $sa.kind -eq 'select' -and $sa.target -eq $victim -and $sa.label -eq 'Dosyayı klasörde göster') ($sa | Out-String)
    TCheck 'eylem: olmayan dosya -> null' ($null -eq (Get-FindingAction (New-Finding 'file:abc' 'RED' 't' 'd' (Join-Path $work 'yok.exe')))) ''
    $quoted = Join-Path $work 'a"b.exe'
    TCheck 'eylem: tirnakli yol -> null' ($null -eq (Get-FindingAction (New-Finding 'file:abc' 'RED' 't' 'd' $quoted))) ''

    # Invoke: sahte baslatici, sahte mesaj; gercek Start-Process yok
    $launched = New-Object Collections.ArrayList
    $msgs = New-Object Collections.ArrayList
    $fake = { param($file, $argText) [void]$launched.Add("$file|$argText") }
    $note = { param($text) [void]$msgs.Add($text) }
    foreach ($bad in 'http://evil', 'file:///C:/Windows/System32/cmd.exe', 'javascript:alert(1)', 'ms-settings:x y', 'windowsdefender2://x') {
        $launched.Clear(); $msgs.Clear()
        $r = Invoke-FindingAction @{ label = 'x'; kind = 'uri'; target = $bad } $fake $note
        TCheck "Invoke reddeder: $bad" (-not $r -and $launched.Count -eq 0 -and $msgs.Count -eq 1 -and $msgs[0] -eq 'Açılamadı. Ayrıntılardaki adımları elle izleyebilirsiniz.') "$r $($launched -join ',')"
    }
    $launched.Clear(); $msgs.Clear()
    $r = Invoke-FindingAction @{ label = 'x'; kind = 'exe'; target = 'C:\Windows\System32\cmd.exe'; args = '' } $fake $note
    TCheck 'Invoke: izinli olmayan exe reddedilir' (-not $r -and $launched.Count -eq 0 -and $msgs.Count -eq 1) ''
    $r = Invoke-FindingAction @{ label = 'x'; kind = 'exe'; target = (Join-Path $sysDir 'mmc.exe'); args = 'evil.msc' } $fake $note
    TCheck 'Invoke: mmc baska arguman reddedilir' (-not $r -and $launched.Count -eq 0) ''
    $launched.Clear(); $msgs.Clear()
    $r = Invoke-FindingAction (Get-FindingAction (New-Finding 'admin' 'YELLOW' 't' 'd')) $fake $note
    TCheck 'Invoke: izinli adres baslatilir' ($r -and $launched.Count -eq 1 -and $launched[0] -eq 'ms-settings:otherusers|' -and $msgs.Count -eq 0) ($launched -join ',')
    $launched.Clear()
    $r = Invoke-FindingAction (Get-FindingAction (New-Finding 'uac' 'YELLOW' 't' 'd')) $fake $note
    TCheck 'Invoke: uac exe baslatilir' ($r -and $launched.Count -eq 1 -and $launched[0] -eq ((Join-Path $sysDir 'UserAccountControlSettings.exe') + '|')) ($launched -join ',')
    $launched.Clear()
    $r = Invoke-FindingAction $sa $fake $note
    TCheck 'Invoke: select explorer /select tek arguman' ($r -and $launched.Count -ge 1 -and $launched[0] -eq ((Join-Path $env:windir 'explorer.exe') + '|/select,"' + $victim + '"')) ($launched -join ',')
    $psExe = Join-Path $sysDir 'WindowsPowerShell\v1.0\powershell.exe'
    $wantOverlay = $psExe + '|-NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -File "' + $SelfPath + '" -Mode Overlay -Path "' + $victim + '"'
    TCheck 'Invoke: select ardindan uyari katmani sureci baslatilir' ($launched.Count -eq 2 -and $launched[1] -eq $wantOverlay) ($launched -join ' ;; ')
    $launched.Clear(); $msgs.Clear()
    $okExplorerBad = Invoke-FindingAction $sa { param($file, $argText) if ($file -like '*powershell.exe') { throw 'boom' } else { [void]$launched.Add($file) } } $note
    TCheck 'Invoke: katman baslatilamazsa eylem yine basarili, mesaj yok' ($okExplorerBad -and $launched.Count -eq 1 -and $msgs.Count -eq 0) ''
    $launched.Clear(); $msgs.Clear()
    $r = Invoke-FindingAction @{ label = 'x'; kind = 'select'; target = $quoted } $fake $note
    TCheck 'Invoke: tirnakli yolda katman da baslamaz' (-not $r -and $launched.Count -eq 0) ''
    $launched.Clear()
    $r = Invoke-FindingAction (Get-FindingAction (New-Finding 'admin' 'YELLOW' 't' 'd')) $fake $note
    TCheck 'Invoke: uri eyleminde katman baslamaz' ($r -and $launched.Count -eq 1) ($launched -join ',')
    $launched.Clear()

    # Tehlikeli dosya uyari katmani: ValidateSet, saf yerlesim, dikdortgen suzgeci
    $paramAttr = (Get-Command (Join-Path $work 'CortmedSecurity.ps1')).Parameters['Mode'].Attributes | Where-Object { $_ -is [Management.Automation.ValidateSetAttribute] }
    TCheck 'katman: Overlay modu ValidateSet icinde' (@($paramAttr.ValidValues) -contains 'Overlay') ($paramAttr.ValidValues -join ',')
    $scr = New-Object Drawing.Rectangle 0, 0, 1920, 1040
    $csz = New-Object Drawing.Size 420, 64
    function InScr($l) { $l.Callout.Left -ge $scr.Left -and $l.Callout.Top -ge $scr.Top -and $l.Callout.Right -le $scr.Right -and $l.Callout.Bottom -le $scr.Bottom }
    $l1 = Get-OverlayLayout (New-Object Drawing.Rectangle 100, 200, 300, 40) $scr $csz
    TCheck 'katman: yer varsa balon sagda' ($l1.Side -eq 'right' -and $l1.Callout.Left -gt 400 -and (InScr $l1)) ($l1.Side)
    TCheck 'katman: ok ucu ogenin kenarinda, tabani balonda' ($l1.Arrow.Count -eq 3 -and $l1.Arrow[0].X -ge 400 -and $l1.Arrow[0].X -le 404 -and $l1.Arrow[1].X -eq $l1.Callout.Left -and $l1.Arrow[2].X -eq $l1.Callout.Left) ($l1.Arrow -join ' ')
    $l2 = Get-OverlayLayout (New-Object Drawing.Rectangle 1500, 200, 300, 40) $scr $csz
    TCheck 'katman: sagda yer yoksa balon solda' ($l2.Side -eq 'left' -and $l2.Callout.Right -lt 1500 -and (InScr $l2)) ($l2.Side)
    $narrow = New-Object Drawing.Rectangle 0, 0, 500, 600
    $l3 = Get-OverlayLayout (New-Object Drawing.Rectangle 100, 200, 300, 40) $narrow $csz
    TCheck 'katman: yanlarda yer yoksa balon altta' ($l3.Side -eq 'below' -and $l3.Callout.Top -gt 240 -and $l3.Callout.Right -le 500) ($l3.Side)
    $l4 = Get-OverlayLayout (New-Object Drawing.Rectangle 100, 540, 300, 40) $narrow $csz
    TCheck 'katman: altta da yer yoksa balon ustte' ($l4.Side -eq 'above' -and $l4.Callout.Bottom -lt 540 -and $l4.Callout.Top -ge 0) ($l4.Side)
    $tiny = New-Object Drawing.Rectangle 0, 0, 300, 100
    $l5 = Get-OverlayLayout (New-Object Drawing.Rectangle 20, 30, 260, 40) $tiny $csz
    TCheck 'katman: hicbir yere sigmasa da ekran icinde kalir' ($l5.Callout.Left -ge 0 -and $l5.Callout.Top -ge 0) ($l5.Callout | Out-String)
    $l6 = Get-OverlayLayout (New-Object Drawing.Rectangle 1000, 2, 300, 40) $scr $csz
    TCheck 'katman: ekranin ust kenarinda balon ekran icinde' ((InScr $l6) -and $l6.Callout.Top -ge 0) ($l6.Callout | Out-String)
    TCheck 'katman: Bounds ogeyi ve balonu kapsar' ($l1.Bounds.Contains($l1.Callout) -and $l1.Bounds.Contains((New-Object Drawing.Rectangle 100, 200, 300, 40))) ($l1.Bounds | Out-String)
    $pb = [Windows.Forms.Screen]::PrimaryScreen.Bounds
    TCheck 'katman: gecerli dikdortgen kabul' ($null -ne (Get-OverlayRectOrNull ($pb.X + 10) ($pb.Y + 10) 300 40)) ''
    TCheck 'katman: bos dikdortgen reddedilir' ($null -eq (Get-OverlayRectOrNull 10 10 0 0)) ''
    TCheck 'katman: ekran disi dikdortgen reddedilir' ($null -eq (Get-OverlayRectOrNull -32000 -32000 300 40)) ''
    TCheck 'katman: sonsuz (Rect.Empty) reddedilir' ($null -eq (Get-OverlayRectOrNull ([double]::PositiveInfinity) ([double]::PositiveInfinity) ([double]::NegativeInfinity) ([double]::NegativeInfinity))) ''
    TCheck 'katman: yol tirnak icerirse sessizce cikar' ($null -eq (Show-DangerOverlay 'C:\a"b.exe')) ''
    $launched.Clear(); $msgs.Clear()
    $r = Invoke-FindingAction @{ label = 'x'; kind = 'select'; target = $quoted } $fake $note
    TCheck 'Invoke: select tirnakli yol reddedilir' (-not $r -and $launched.Count -eq 0) ''
    $launched.Clear(); $msgs.Clear()
    $r = Invoke-FindingAction @{ label = 'x'; kind = 'uri'; target = 'ms-settings:network-status' } { param($f, $a) throw 'boom' } $note
    TCheck 'Invoke: baslatici hata verirse mesaj' (-not $r -and $msgs.Count -eq 1) ''

    # Ayrintilar penceresi: eylem dugmesi Kapat'in solunda; eylemsiz bulguda yok
    $rf = New-ReportForm (New-Finding 'defender-off' 'RED' 'Virüs koruması kapalı' 'detay')
    $rb = Btn $rf 'Virüs korumasını aç'
    $rc = Btn $rf 'Kapat'
    TCheck 'ayrintilar: eylem dugmesi var' ($null -ne $rb) ''
    TCheck 'ayrintilar: eylem dugmesi Kapatin solunda' ($rb -and $rc -and $rb.Parent.Controls.IndexOf($rb) -lt $rb.Parent.Controls.IndexOf($rc)) ''
    TCheck 'ayrintilar: gosterilmedi' (-not $rf.Visible) ''
    $rf.Dispose()
    $rf2 = New-ReportForm (New-Finding 'nope' 'YELLOW' 'Baslik' 'detay')
    TCheck 'ayrintilar: eylemsiz bulguda ek dugme yok' ((@(All-Controls $rf2 | Where-Object { $_ -is [Windows.Forms.Button] }).Count) -eq 1) ''
    $rf2.Dispose()
    $rf3 = New-ReportForm (New-Finding 'file:abc' 'RED' 'Tehdit' 'detay' $victim)
    TCheck 'ayrintilar: dosya icin klasorde goster dugmesi' ($null -ne (Btn $rf3 'Dosyayı klasörde göster')) ''
    $rf3.Dispose()
    $cf = New-FindingCard (New-Finding 'firewall' 'YELLOW' 'Güvenlik duvarı kapalı' 'detay') 700 $null $null
    TCheck 'kart: eylem dugmesi Ayrintilarin yaninda' ($null -ne (Btn $cf 'Güvenlik duvarını aç') -and $null -ne (Btn $cf 'Ayrıntılar')) ''
    $cf.Dispose()

    # Ayrintilarda gezinme tarifi kalmadi: metinler dugmeye yonlendirir
    $src = [IO.File]::ReadAllText((Join-Path $RepoRoot 'windows\CortmedSecurity.ps1'), [Text.Encoding]::UTF8)
    TCheck 'metin: Baslat menusunden / Denetim Masasi tarifi kalmadi' ($src -notmatch 'Başlat menüsünden "Windows|Denetim Masası >|Görev Yöneticisi > Başlangıç') ''
} catch {
    TCheck 'tepsi testleri calisti' $false $_.Exception.Message
} finally {
    Remove-Item $work -Recurse -Force -ErrorAction SilentlyContinue
}
exit $script:trayFails
