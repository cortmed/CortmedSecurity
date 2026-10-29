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
    $grp = @(Get-AdviceGroups $sum.advice | Where-Object { $_.cat.title -eq 'Durdurulan programlar' })
    TCheck '"Durdurulan programlar" grubu iki bulguyla' ($grp.Count -eq 1 -and @($grp[0].items).Count -eq 2) ''
    TCheck '"Durdurulan programlar" aciklamasi' ($grp.Count -eq 1 -and $grp[0].cat.text -eq 'Cortmed bu programları durdurdu. Kapatmayı seçtiyseniz bir şey yapmanıza gerek yok.') ''
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
} catch {
    TCheck 'tepsi testleri calisti' $false $_.Exception.Message
} finally {
    Remove-Item $work -Recurse -Force -ErrorAction SilentlyContinue
}
exit $script:trayFails
