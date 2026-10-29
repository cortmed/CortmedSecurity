# Davranış Bekçisi (Faz 2) Uygulama Planı

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Windows'ta çalışan programların davranışını Sysmon olaylarından izleyip puanlayan, 80+ puanda program ağacını dondurup kullanıcıya "Durdur / İzin ver" diye soran CortmedGuard hizmetini eklemek.

**Architecture:** Saf C# çekirdek (`windows/guard/Core/*`: olay modeli, sınıflandırıcı, süreç ağacı, puan tahtası, kurallar) test edilebilir ayrı bir katman. Üstünde ince bir hizmet kabuğu (`windows/guard/Service/*`: Sysmon okuyucu, süreç kontrolü, named pipe sunucusu, ServiceBase). Tepsi tarafı mevcut `CortmedSecurity.ps1`'e pipe istemcisi ve soru penceresi ekler. Kurulumun yetkili kısmı ayrı bir `Install-Guard.ps1`.

**Tech Stack:** C# 5 (.NET Framework 4.8, Windows'taki `csc.exe` ile kurulumda derlenir), `System.Web.Extensions` (JavaScriptSerializer), `System.ServiceProcess`, P/Invoke (`ntdll!NtSuspendProcess/NtResumeProcess`, `wintrust!WinVerifyTrust`), Sysmon (Sysinternals), PowerShell 5.1 (WinForms tepsi), Python (gece imzalama).

**Spec:** `docs/superpowers/specs/2026-10-29-davranis-bekcisi-design.md`

## Global Constraints

- Hedef: Windows 10/11, .NET Framework 4.8; C# 5 sözdizimi (tuple, `$""`, `?.`, `nameof` yok) çünkü `csc.exe` v4.
- Hizmet adı `CortmedGuard`, LocalSystem; ikili `C:\Program Files\Cortmed\CortmedGuard.exe`; ayar/kural/kayıt `C:\ProgramData\Cortmed\`.
- ACL: SYSTEM ve Administrators yazar, Users okur (Program Files\Cortmed ve ProgramData\Cortmed).
- Pipe: `\\.\pipe\CortmedGuard`; ACL SYSTEM tam, INTERACTIVE okuma/yazma; mesaj başına en fazla 4096 bayt, satır başına bir JSON.
- Eşikler: dondur ≥ 80, uyar 50–79, kayıt < 50; puan penceresi 300 saniye; toplu değişiklik: 10 saniyede 50'den fazla belge.
- Puanlar: açılışa ekleme +35, başka programın dosyası +50, gizlenmiş komut +30, koruma kapatma +60, kod sokma +50, LSASS +70, toplu belge değişikliği +70, Program Files'ta geçerli imzalı −30.
- Asla dondurulmaz: System, smss, csrss, wininit, winlogon, services, lsass, explorer, CortmedGuard, CortmedSecurity.
- Cortmed sormadan program kapatmaz. Cevap yoksa ağaç donuk kalır; 10 dakika sonra kalıcı bildirim.
- Kurallar dosyası imza doğrulanmadan yüklenmez (mevcut ECDSA P-256 anahtarı, `Cortmed.Signing.Verify`).
- Sysmon yalnızca resmi adresten (`https://download.sysinternals.com/files/Sysmon.zip`) ve Authenticode imzalayanı "Microsoft Corporation" ise kurulur; önceden kurulu Sysmon'a dokunulmaz.
- Kullanıcıya görünen bütün metinler Türkçe, "siz" diliyle ve sade.

## Review Focus

1. **Önceden kurulu Sysmon farklı bir ayarla çalışıyor** → bekçi çökmemeli; gelen olaylarla çalışmalı, panelde "Sysmon başka bir ayarla çalışıyor; bazı davranışlar görülmeyebilir" bilgisi çıkmalı. Test: Task 10'da `Install-Guard.ps1 -WhatIf` önceden kurulu Sysmon senaryosu.
2. **Tepsi açık değilken dondurma** (oturum açılmamış ya da tepsi kapatılmış) → soru bekletilmeli, tepsi bağlanınca hemen gönderilmeli. Test: Task 8 `PendingPromptsAreReplayedOnConnect`.
3. **Dondurulan programın ağacında sonradan yeni alt süreç doğması** (dondurma sırasında yarış) → yeni çocuk da dondurulmalı. Test: Task 8 `ChildStartedDuringFreezeIsSuspended`.
4. **Aynı program için tekrar tekrar soru** (kullanıcı "İzin ver" dedikten sonra) → bir daha sorulmamalı, izin listesi yeniden başlatmada da korunmalı. Test: Task 8 `AllowedHashIsNotAskedAgainAfterRestart`.
5. **Pipe'a başka bir yerel programın sahte cevap göndermesi** → bilinmeyen id, büyük mesaj, bozuk JSON reddedilmeli; hizmet düşmemeli. Test: Task 7 `RejectsUnknownIdOversizedAndMalformed`.

---

## Dosya Yapısı

| Dosya | Sorumluluk |
|---|---|
| `windows/guard/Core/GuardEvent.cs` | Olay modeli (`GuardEvent`), `Behavior` enum, `Hit` |
| `windows/guard/Core/BehaviorRules.cs` | `behavior-rules.json` modeli ve yükleme |
| `windows/guard/Core/Classifier.cs` | Tek olay → davranış isabetleri |
| `windows/guard/Core/ProcessTree.cs` | pid → ebeveyn/imaj, kök bulma, alt süreçler |
| `windows/guard/Core/ScoreBoard.cs` | Ağaç başına puan penceresi, toplu değişiklik sayacı, karar |
| `windows/guard/Service/FileTrust.cs` | Başlangıç puanı: imza (WinVerifyTrust) + konum |
| `windows/guard/Service/ProcessControl.cs` | Dondur / devam / ağacı kapat, asla-dondurma listesi |
| `windows/guard/Service/SysmonReader.cs` | Sysmon olay günlüğü → `GuardEvent` |
| `windows/guard/Service/GuardPipe.cs` | Pipe sunucusu ve mesaj doğrulama |
| `windows/guard/Service/GuardService.cs` | `ServiceBase`; bileşenleri bağlar, bekleyen sorular, izin listesi, kural güncelleme, `--console` modu |
| `windows/guard/sysmon-cortmed.xml` | Cortmed Sysmon ayarı |
| `engine/rules/behavior_rules.json` | Puanlar, eşikler, istisnalar |
| `windows/CortmedEngine.cs` (değişir) | `GuardClient` (tepsi tarafı pipe istemcisi) |
| `windows/CortmedSecurity.ps1` (değişir) | Soru penceresi, panel durumu, bulgu ekleme |
| `windows/Install-Guard.ps1`, `windows/Uninstall-Guard.ps1` | Yetkili kurulum/kaldırma |
| `windows/Install.ps1`, `windows/Uninstall.ps1`, `make-windows-package.ps1` (değişir) | Yetkili parçayı çağırma, pakete ekleme |
| `engine/sign_db.py`, `.github/workflows/update-db.yml` (değişir) | `behavior_rules.json` imzalı yayın |
| `tests/guard/GuardTests.cs`, `tests/guard/run.ps1`, `tests/guard/fixtures/*.json` | Test çalıştırıcı ve örnek olaylar |
| `windows/guard/Test/CortmedBehaviorTest.cs` | Zararsız davranış test programı |

**Test çalıştırıcı:** `tests/guard/run.ps1` Core ve Service kaynaklarını `GuardTests.cs` ile tek bir konsol exe'ye derler ve çalıştırır. Her test `[Test]` öznitelikli statik metot; çıktı `PASS <ad>` / `FAIL <ad>: <mesaj>`, son satır `n geçti, m kaldı`. Çıkış kodu kalan sayısı.

---

### Task 1: Olay modeli, kurallar ve test çalıştırıcı

**Files:**
- Create: `windows/guard/Core/GuardEvent.cs`, `windows/guard/Core/BehaviorRules.cs`, `engine/rules/behavior_rules.json`
- Create: `tests/guard/GuardTests.cs`, `tests/guard/run.ps1`

**Interfaces:**
- Produces:
  - `namespace Cortmed.Guard`
  - `enum Behavior { Persistence, TamperOtherApp, HiddenScript, DisableProtection, Injection, LsassAccess, MassFileChange }`
  - `class GuardEvent { int EventId; DateTime Time; int Pid; int ParentPid; string Image; string ParentImage; string CommandLine; string TargetObject; string TargetFilename; int TargetPid; string TargetImage; string Hashes; }` (alanlar public)
  - `class Hit { Behavior Behavior; int Pid; string Reason; }` — `Pid` puanın yazılacağı süreç (çoğunlukla olayı yapan, bazen ebeveyn).
  - `class BehaviorRules { int FreezeAt; int WarnAt; int WindowSeconds; int MassFileCount; int MassFileSeconds; int TrustedLocationBonus; Dictionary<Behavior,int> Points; Dictionary<Behavior,string> Reasons; HashSet<string> NeverFreeze; HashSet<string> TrustedImages; static BehaviorRules Parse(string json); }`
  - `tests/guard/run.ps1` — çalıştırma: `powershell -File tests/guard/run.ps1`

- [ ] **Step 1: `behavior_rules.json` dosyasını Global Constraints'teki değerlerle yaz**
  Anahtarlar: `freezeAt` 80, `warnAt` 50, `windowSeconds` 300, `massFileCount` 50, `massFileSeconds` 10, `trustedLocationBonus` -30, `points` (her Behavior adı → puan), `neverFreeze` (küçük harf exe adları), `trustedImages` (MsMpEng.exe, svchost.exe, CortmedGuard.exe, CortmedSecurity.exe, TiWorker.exe, TrustedInstaller.exe).
  `reasons` birebir şu metinler:
  Persistence "Kendini açılışa eklemeye çalıştı." · TamperOtherApp "Başka bir programın (Discord/tarayıcı) dosyalarını değiştirmeye çalıştı." · HiddenScript "Gizlenmiş bir komut başlattı." · DisableProtection "Virüs korumasını kapatmaya çalıştı." · Injection "Başka bir programın içine kod sokmaya çalıştı." · LsassAccess "Windows'un şifre belleğine erişmeye çalıştı." · MassFileChange "Kısa sürede çok sayıda belgeyi değiştirdi."

- [ ] **Step 2: Başarısız testi yaz**

```csharp
[Test] static void RulesParseValuesFromJson() {
    var r = BehaviorRules.Parse(File.ReadAllText(RepoPath("engine/rules/behavior_rules.json")));
    Assert(r.FreezeAt == 80 && r.WarnAt == 50 && r.WindowSeconds == 300);
    Assert(r.Points[Behavior.LsassAccess] == 70 && r.Points[Behavior.Persistence] == 35);
    Assert(r.NeverFreeze.Contains("lsass.exe") && r.NeverFreeze.Contains("explorer.exe"));
    Assert(r.Reasons[Behavior.Persistence] == "Kendini açılışa eklemeye çalıştı.");
}
```

- [ ] **Step 3: `run.ps1` ile çalıştır, FAIL gör** — beklenen: derleme hatası ya da `FAIL RulesParseValuesFromJson`.
- [ ] **Step 4: `GuardEvent.cs` ve `BehaviorRules.Parse` yaz** — JavaScriptSerializer ile; bilinmeyen davranış adı → `InvalidDataException`.
- [ ] **Step 5: `run.ps1` → `PASS RulesParseValuesFromJson`**
- [ ] **Step 6: Commit** — `git commit -m "guard: olay modeli, kurallar ve test calistirici"`

---

### Task 2: Sınıflandırıcı (olay → isabet)

**Files:**
- Create: `windows/guard/Core/Classifier.cs`, `tests/guard/fixtures/*.json`
- Modify: `tests/guard/GuardTests.cs`

**Interfaces:**
- Consumes: `GuardEvent`, `Hit`, `Behavior`, `BehaviorRules` (Task 1)
- Produces: `class Classifier { Classifier(BehaviorRules rules); List<Hit> Classify(GuardEvent e); }`

Kurallar (spec Bölüm 3–4):
- Persistence: olay 13 ve `TargetObject` `\CurrentVersion\Run\` ya da `\RunOnce\` içerir → olayı yapan; olay 11 ve `TargetFilename` `\Start Menu\Programs\Startup\` içerir → olayı yapan; olay 1, imaj `schtasks.exe`, komut satırında `/create` → **ebeveyn** pid.
- TamperOtherApp: olay 11, hedef `\discord_desktop_core\` ya da `\User Data\<profil>\Extensions\` altında, ve olayı yapan imaj o uygulamanın kendi klasöründe değil.
- HiddenScript: olay 1, imaj powershell/pwsh/cmd/mshta/wscript/cscript ve komut satırı `-enc`, `-encodedcommand`, `-w hidden`, `-windowstyle hidden` ya da `frombase64string` içerir (büyük/küçük harf duyarsız) → **ebeveyn** pid.
- DisableProtection: olay 13 ve hedef `\Windows Defender\Exclusions\` ya da `DisableRealtimeMonitoring` içerir; olay 1 ve komut satırı `Add-MpPreference` ya da `Set-MpPreference` + `-Disable` içerir → **ebeveyn**.
- Injection: olay 8 ve `Pid != TargetPid` → olayı yapan.
- LsassAccess: olay 10, hedef imaj `\lsass.exe` ile biter, olayı yapan `TrustedImages` içinde değil.
- MassFileChange burada isabet üretmez; olay 11'in belge klasöründe olduğunu `Classifier.IsDocumentWrite(GuardEvent e)` söyler (Documents, Desktop, Pictures, Videos, Music altında).

- [ ] **Step 1: Her davranış için bir fixture yaz** — `fixtures/persistence-runkey.json`, `startup-folder.json`, `schtasks-create.json`, `discord-core.json`, `hidden-powershell.json`, `defender-exclusion.json`, `remote-thread.json`, `lsass-access.json`, `benign-chrome-update.json` (imzalı Chrome güncellemesi, isabet yok).
- [ ] **Step 2: Başarısız testleri yaz**

```csharp
[Test] static void EachFixtureProducesExpectedBehavior() {
    // fixture içindeki "expect": {"behavior":"Persistence","pidIs":"parent"|"self"} alanına göre
    foreach (var f in Fixtures()) {
        var hits = new Classifier(Rules()).Classify(f.Event);
        if (f.ExpectBehavior == null) { Assert(hits.Count == 0, f.Name); continue; }
        Assert(hits.Count == 1 && hits[0].Behavior == f.ExpectBehavior, f.Name);
        Assert(hits[0].Pid == (f.PidIsParent ? f.Event.ParentPid : f.Event.Pid), f.Name);
        Assert(hits[0].Reason == Rules().Reasons[f.ExpectBehavior.Value], f.Name);
    }
}
[Test] static void DiscordUpdaterWritingItsOwnCoreIsNotTamper() { /* imaj ...\Discord\Update.exe, hedef aynı Discord klasörü → 0 isabet */ }
```

- [ ] **Step 3: Çalıştır, FAIL gör**
- [ ] **Step 4: `Classifier.Classify` ve `IsDocumentWrite` yaz** — tüm yol karşılaştırmaları `OrdinalIgnoreCase`.
- [ ] **Step 5: Çalıştır, PASS gör**
- [ ] **Step 6: Commit** — `"guard: davranis siniflandirici"`

---

### Task 3: Süreç ağacı ve puan tahtası

**Files:**
- Create: `windows/guard/Core/ProcessTree.cs`, `windows/guard/Core/ScoreBoard.cs`
- Modify: `tests/guard/GuardTests.cs`

**Interfaces:**
- Consumes: `GuardEvent`, `Hit`, `BehaviorRules`
- Produces:
  - `class ProcessTree { void OnProcessStart(GuardEvent e); void OnProcessExit(int pid); int RootOf(int pid); List<int> Subtree(int rootPid); string ImageOf(int pid); }` — kök: ebeveyni bilinmeyen ya da ebeveyni `explorer.exe`/`services.exe` olan en üst Cortmed dışı süreç.
  - `enum DecisionLevel { Log, Warn, Freeze }`
  - `class Decision { DecisionLevel Level; int RootPid; int Score; List<string> Reasons; }`
  - `class ScoreBoard { ScoreBoard(BehaviorRules r); Decision Add(int rootPid, int baseScore, Hit hit, DateTime now); Decision AddDocumentWrite(int rootPid, int baseScore, DateTime now); void Forget(int rootPid); }`
    - `baseScore` her kök için ilk eklemede bir kez sayılır.
    - `WindowSeconds` dışındaki isabetler düşer. Aynı davranış bir kökte bir kez sayılır, nedeni bir kez yazılır.
    - Bir kök Freeze kararı aldıktan sonra `Forget` çağrılana kadar yeni Freeze kararı üretilmez (tekrar soru yok).

- [ ] **Step 1: Başarısız testleri yaz**

```csharp
[Test] static void RootOfGrandchildIsTopProcess() { /* explorer→a.exe→cmd→powershell: RootOf(powershell)==a */ }
[Test] static void ScoreCrossesFreezeWithBaseAndTwoBehaviors() {
    var sb = new ScoreBoard(Rules()); var t = DateTime.Now;
    Assert(sb.Add(100, 30, Hit(Behavior.Persistence), t).Level == DecisionLevel.Warn);      // 30+35=65
    var d = sb.Add(100, 30, Hit(Behavior.TamperOtherApp), t.AddSeconds(5));                  // 65+50=115
    Assert(d.Level == DecisionLevel.Freeze && d.Reasons.Count == 2);
}
[Test] static void HitsOlderThanWindowExpire() { /* 301 sn sonra yeni isabet tek başına sayılır */ }
[Test] static void SameBehaviorCountsOnce() { /* iki Persistence → 35, iki neden değil bir neden */ }
[Test] static void FiftyOneDocumentWritesInTenSecondsIsMassChange() { /* 51. yazımda MassFileChange (+70) eklenir */ }
[Test] static void NoSecondFreezeUntilForget() { }
```

- [ ] **Step 2: Çalıştır, FAIL gör**
- [ ] **Step 3: `ProcessTree` ve `ScoreBoard` yaz**
- [ ] **Step 4: Çalıştır, PASS gör**
- [ ] **Step 5: Commit** — `"guard: surec agaci ve puan tahtasi"`

---

### Task 4: Başlangıç puanı (imza + konum)

**Files:**
- Create: `windows/guard/Service/FileTrust.cs`
- Modify: `tests/guard/GuardTests.cs`

**Interfaces:**
- Produces: `static class FileTrust { static int BaseScore(string imagePath, BehaviorRules r); static bool IsValidlySigned(string path); static string Publisher(string path); }`
  - Geçerli imzalı ve `Program Files` / `Program Files (x86)` / `Windows` altında → `r.TrustedLocationBonus` (−30).
  - Geçerli imzalı başka yerde → 0.
  - İmzasız → 15; ayrıca kullanıcı klasöründe (Downloads, AppData, Temp, Desktop, Public) → +15.
  - Dosya yok / okunamıyor → 15.
  - `IsValidlySigned`: `WinVerifyTrust` (`WINTRUST_ACTION_GENERIC_VERIFY_V2`, iptal kontrolü yok, UI yok).

- [ ] **Step 1: Başarısız testleri yaz**

```csharp
[Test] static void NotepadIsTrusted() { Assert(FileTrust.BaseScore(@"C:\Windows\System32\notepad.exe", Rules()) == -30); }
[Test] static void UnsignedExeInTempScoresThirty() { /* csc ile Temp'e boş exe derle → 30 */ }
[Test] static void MissingFileScoresFifteen() { }
```

- [ ] **Step 2–4: FAIL → uygula → PASS**
- [ ] **Step 5: Commit** — `"guard: imza ve konum baslangic puani"`

---

### Task 5: Süreç kontrolü (dondur / devam / kapat)

**Files:**
- Create: `windows/guard/Service/ProcessControl.cs`
- Modify: `tests/guard/GuardTests.cs`

**Interfaces:**
- Produces: `static class ProcessControl { static bool CanFreeze(int pid, BehaviorRules r); static List<int> FreezeTree(List<int> pids, BehaviorRules r); static void ResumeTree(List<int> pids); static void KillTree(List<int> pids); }`
  - `NtSuspendProcess` / `NtResumeProcess` (ntdll), `Process.Kill` ağacı yapraktan köke.
  - `CanFreeze` false: `NeverFreeze`'deki imaj adı, pid 0/4, mevcut süreç.
  - `FreezeTree` dondurabildiklerini döndürür; erişim hatası listeden çıkarılır, istisna fırlatmaz.

- [ ] **Step 1: Başarısız testleri yaz**

```csharp
[Test] static void FreezeAndResumeChildProcess() {
    var p = Process.Start(new ProcessStartInfo("powershell", "-NoProfile -Command Start-Sleep 30") { CreateNoWindow = true, UseShellExecute = false });
    var frozen = ProcessControl.FreezeTree(new List<int> { p.Id }, Rules());
    Assert(frozen.Count == 1 && AllThreadsSuspended(p));
    ProcessControl.ResumeTree(frozen); Assert(!AllThreadsSuspended(p));
    ProcessControl.KillTree(frozen); Assert(p.WaitForExit(5000));
}
[Test] static void ExplorerAndLsassAreNeverFrozen() { }
```

- [ ] **Step 2–4: FAIL → uygula → PASS** (`AllThreadsSuspended`: `p.Refresh()`, her `ProcessThread.WaitReason == Suspended`)
- [ ] **Step 5: Commit** — `"guard: dondurma, devam ettirme ve kapatma"`

---

### Task 6: Sysmon okuyucu

**Files:**
- Create: `windows/guard/Service/SysmonReader.cs`, `tests/guard/fixtures/sysmon-event-1.xml`, `sysmon-event-13.xml`
- Modify: `tests/guard/GuardTests.cs`

**Interfaces:**
- Produces:
  - `class SysmonReader : IDisposable { SysmonReader(Action<GuardEvent> onEvent); void Start(); bool IsSysmonRunning(); }` — `EventLogWatcher` ile `Microsoft-Windows-Sysmon/Operational`, olay kimlikleri 1, 5 (süreç bitişi), 8, 10, 11, 13.
  - `static GuardEvent SysmonReader.FromXml(string eventXml)` — `EventData/Data[@Name]` alanlarını eşler: ProcessId/ParentProcessId/Image/ParentImage/CommandLine/TargetObject/TargetFilename/Hashes; olay 8 ve 10 için `SourceProcessId`→Pid, `SourceImage`→Image, `TargetProcessId`→TargetPid, `TargetImage`.

- [ ] **Step 1: İki gerçek Sysmon olay XML'ini fixture olarak kaydet** (Sandbox'ta `Get-WinEvent ... | % ToXml`)
- [ ] **Step 2: Başarısız testi yaz** — `FromXmlMapsProcessCreateAndRegistryFields`: pid, ebeveyn, imaj, komut satırı, hedef nesne beklenen değerlerde.
- [ ] **Step 3–4: FAIL → uygula → PASS**
- [ ] **Step 5: Commit** — `"guard: sysmon olay okuyucu"`

---

### Task 7: Pipe sunucusu ve istemcisi

**Files:**
- Create: `windows/guard/Service/GuardPipe.cs`
- Modify: `windows/CortmedEngine.cs` (yeni `GuardClient` sınıfı), `tests/guard/GuardTests.cs`

**Interfaces:**
- Produces (sunucu):
  - `class Prompt { string Id; string Program; string Path; string Publisher; int Score; List<string> Reasons; }`
  - `class GuardPipe : IDisposable { GuardPipe(string name, Func<string,string,bool> onAnswer); void Start(); void SendPrompt(Prompt p); void SendStatus(bool sysmonOk, bool sysmonPreexisting); bool HasClient { get; } }`
  - Mesajlar (satır başına JSON): sunucu→istemci `{"type":"ask",...Prompt alanları}` ve `{"type":"status","sysmon":true,"preexisting":false}`; istemci→sunucu `{"type":"answer","id":"..","decision":"kill"|"allow"}`.
  - `onAnswer(id, decision)` false dönerse mesaj yok sayılır.
  - Reddedilir: 4096 bayttan uzun satır, bozuk JSON, `type != "answer"`, karar iki değerden biri değil.
  - ACL: `PipeSecurity` — LocalSystem FullControl, `WellKnownSidType.InteractiveSid` ReadWrite.
- Produces (istemci, `CortmedEngine.cs`, namespace `Cortmed`):
  - `class GuardClient : IDisposable { GuardClient(string pipeName); bool Connected { get; } bool SysmonOk { get; } bool SysmonPreexisting { get; } bool TryDequeuePrompt(out string promptJson); void Answer(string id, string decision); }` — arka plan iş parçacığında bağlanır/yeniden bağlanır (5 sn), gelen `ask` satırlarını kuyruğa koyar, `status`'u alanlara yazar.

- [ ] **Step 1: Başarısız testleri yaz**

```csharp
[Test] static void PromptRoundTripsThroughPipe() { /* test pipe adı; SendPrompt → client.TryDequeuePrompt; client.Answer → onAnswer("id1","kill") */ }
[Test] static void RejectsUnknownIdOversizedAndMalformed() { /* onAnswer bilinmeyen id için false; 5000 baytlık satır ve "{bozuk" sunucuyu düşürmez, sonraki geçerli cevap işlenir */ }
```

- [ ] **Step 2–4: FAIL → uygula → PASS**
- [ ] **Step 5: Commit** — `"guard: pipe sunucusu ve tepsi istemcisi"`

---

### Task 8: CortmedGuard hizmeti (bağlama, bekleyen sorular, izin listesi, kural güncellemesi)

**Files:**
- Create: `windows/guard/Service/GuardService.cs`
- Modify: `tests/guard/GuardTests.cs`

**Interfaces:**
- Consumes: Task 1–7'nin tamamı; `Cortmed.Signing.Verify` (`windows/CortmedEngine.cs`)
- Produces:
  - `class GuardEngine { GuardEngine(BehaviorRules r, string dataDir, IProcessControl control, IPromptSink sink); void OnEvent(GuardEvent e); bool OnAnswer(string id, string decision); void OnClientConnected(); }` — saf mantık; `OnAnswer` bekleyen soru yoksa false döner ve `GuardPipe`'ın `onAnswer` geri çağrısına doğrudan bağlanır; testler sahte `IProcessControl`/`IPromptSink` kullanır.
  - `interface IProcessControl { List<int> FreezeTree(List<int> pids); void ResumeTree(List<int> pids); void KillTree(List<int> pids); }` (Task 5'in gerçek sarmalayıcısı)
  - `interface IPromptSink { bool HasClient { get; } void Send(Prompt p); }`
  - `class GuardService : ServiceBase` — `OnStart`: kuralları `ProgramData\Cortmed\behavior-rules.json` + `.sig` ile doğrular (başarısızsa son geçerli kopya `behavior-rules.json.good`), `SysmonReader`, `GuardPipe`, 24 saatte bir kural güncellemesi (`DefaultUpdateUrl` + `/manifest.json`, `/manifest.sig`, `/behavior_rules.json`, `Signing.Verify` + SHA-256), 30 saniyede bir Sysmon kontrolü (durmuşsa `sc start Sysmon64`).
  - `static int Main(string[] args)` — `--console` hizmet olmadan çalıştırır; `--replay <klasör>` fixture olaylarını sırayla `GuardEngine`'e verir ve kararları yazar.
  - Kalıcı dosyalar (`ProgramData\Cortmed`): `allowed.txt` (SHA-256, satır başına), `pending.json`, `guard.log`.
  - Akış: süreç başlangıcı → `ProcessTree` + `FileTrust.BaseScore` (kök için önbellekli) → `Classifier` → `ScoreBoard` → Freeze ise: kökün imaj SHA-256'sı `allowed.txt`'te ise sadece kayıt; değilse `FreezeTree(Subtree(root))`, `Prompt` oluştur, `pending.json`'a yaz, tepsi bağlıysa gönder. Warn ise `guard.log`'a ve `ProgramData\Cortmed\findings.json`'a (tepsi okur) ekle.
  - Dondurulmuş bir kökün ağacında yeni süreç başlarsa hemen dondur.
  - `OnAnswer`: `kill` → `KillTree`, `findings.json`'a RED bulgu; `allow` → `ResumeTree`, hash'i `allowed.txt`'e ekle, `ScoreBoard.Forget(root)`.

- [ ] **Step 1: Başarısız testleri yaz**

```csharp
[Test] static void ReplayPersistencePlusTamperFreezesAndAsks() { /* replay → sahte control.FreezeTree çağrıldı, sink.Send 1 kez, Reasons 2 */ }
[Test] static void KillAnswerKillsTreeAndRecordsFinding() { }
[Test] static void AllowAnswerResumesAndPersistsHash() { }
[Test] static void AllowedHashIsNotAskedAgainAfterRestart() { /* yeni GuardEngine aynı dataDir → aynı replay → Freeze yok */ }
[Test] static void PendingPromptsAreReplayedOnConnect() { /* sink.HasClient=false iken Freeze; sonra OnClientConnected → Send */ }
[Test] static void ChildStartedDuringFreezeIsSuspended() { /* Freeze sonrası aynı kökten olay 1 → FreezeTree yeni pid ile */ }
[Test] static void TamperedRulesFallBackToLastGood() { /* .sig tutmaz → .good yüklenir, log satırı */ }
```

- [ ] **Step 2–4: FAIL → uygula → PASS**
- [ ] **Step 5: Commit** — `"guard: hizmet motoru, bekleyen sorular ve izin listesi"`

---

### Task 9: Sysmon ayarı ve imzalı kural yayını

**Files:**
- Create: `windows/guard/sysmon-cortmed.xml`
- Modify: `engine/sign_db.py` (`FILES`'a `behavior_rules.json`), `.github/workflows/update-db.yml` (`cp engine/rules/behavior_rules.json engine/dist/`, yükleme listesine ekle)

**Interfaces:**
- Produces: Sysmon ayarı yalnızca olay 1, 5, 8, 10 (hedef `lsass.exe`), 11 (Startup, `discord_desktop_core`, `\Extensions\`, Documents/Desktop/Pictures/Videos/Music), 13 (`\CurrentVersion\Run`, `\RunOnce`, `\Windows Defender\`) için `include` kuralı içerir; diğer her şey kapalı.

- [ ] **Step 1: Test** — `tests/guard/run.ps1` içine: `sysmon-cortmed.xml` geçerli XML ve `schemaversion` öz niteliği var; `sign_db.py` yerelde çalıştırılınca `manifest.json` içinde `behavior_rules.json` var.
- [ ] **Step 2–4: FAIL → uygula → PASS**
- [ ] **Step 5: Commit + push** — `"guard: sysmon ayari ve imzali davranis kurallari"`; Actions'ta *Run workflow* → `db-latest`'te `behavior_rules.json` görünür.

---

### Task 10: Yetkili kurulum ve kaldırma

**Files:**
- Create: `windows/Install-Guard.ps1`, `windows/Uninstall-Guard.ps1`
- Modify: `windows/Install.ps1` (sonunda yetkili parçayı çağırır), `windows/Uninstall.ps1`, `make-windows-package.ps1` (`guard/` klasörünü ve iki betiği pakete ekler)

**Interfaces:**
- Produces:
  - `Install-Guard.ps1 -Source <paket klasörü> [-WhatIf]` — yönetici değilse kendini `-Verb RunAs` ile yeniden başlatır. Adımlar: `Program Files\Cortmed` ve `ProgramData\Cortmed` oluştur + ACL; `guard\*.cs` ve `CortmedEngine.cs`'yi Program Files'a kopyala ve **orada** `csc /target:exe /out:CortmedGuard.exe /reference:System.ServiceProcess.dll,System.Web.Extensions.dll,System.Core.dll` ile derle; kuralları + imzayı ProgramData'ya kopyala; Sysmon yoksa resmi zip'i indir → `Get-AuthenticodeSignature` geçerli ve imzalayan CN'si "Microsoft Corporation" → `Sysmon64.exe -accepteula -i sysmon-cortmed.xml`, `ProgramData\Cortmed\sysmon-installed-by-cortmed` işareti; Sysmon zaten varsa dokunma, `sysmon-preexisting` işareti; `sc.exe create CortmedGuard binPath= ... start= auto obj= LocalSystem`, `sc.exe failure CortmedGuard reset= 86400 actions= restart/5000/restart/5000/restart/5000`, `sc.exe start`.
  - `Uninstall-Guard.ps1` — hizmeti durdur/sil; `sysmon-installed-by-cortmed` varsa `Sysmon64.exe -u`; iki klasörü sil.
  - `Install.ps1`: kullanıcı kurulumundan sonra `Install-Guard.ps1` çağrılır; UAC reddedilirse "Davranış bekçisi kurulmadı; panelden sonra açabilirsiniz" yazar ve devam eder.

- [ ] **Step 1: Test** — `Install-Guard.ps1 -WhatIf` (yönetici gerekmez) yapılacak işlerin listesini yazar; iki senaryo: Sysmon yok → "Sysmon kurulacak", Sysmon var → "Sysmon önceden kurulu, dokunulmayacak".
- [ ] **Step 2–4: FAIL → uygula → PASS**
- [ ] **Step 5: Windows Sandbox'ta gerçek kurulum** — `Get-Service CortmedGuard` Running, `Get-Service Sysmon64` Running, `icacls "C:\Program Files\Cortmed"` Users için sadece okuma; ardından `Kaldir.bat` → ikisi de yok.
- [ ] **Step 6: Commit** — `"guard: yetkili kurulum ve kaldirma"`

---

### Task 11: Tepsi entegrasyonu (soru penceresi, panel, bulgular)

**Files:**
- Modify: `windows/CortmedSecurity.ps1`

**Interfaces:**
- Consumes: `Cortmed.GuardClient` (Task 7), `ProgramData\Cortmed\findings.json` (Task 8)
- Produces:
  - `Show-GuardPrompt($promptJson)` — en üstte, koyu tema; başlık "Cortmed şüpheli bir programı durdurdu: <program>", neden listesi, düğmeler **"Programı kapat (önerilen)"** / **"İzin ver, devam etsin"** / "Ayrıntılar". Seçim → `GuardClient.Answer(id, 'kill'|'allow')`. Pencere kapatılırsa cevap gönderilmez (program donuk kalır).
  - Bekçi (`Start-Watcher`) zamanlayıcısı her tikte `TryDequeuePrompt` yapar; 10 dakika cevapsız kalan soru için `Show-Toast ... -Sticky`.
  - `Get-StatusSummary` `findings.json`'daki davranış bulgularını tehditlere ekler.
  - Panel durum kartına dördüncü kontrol: "Davranış bekçisi" — hizmet çalışıyor ve Sysmon tamam → ✓; önceden kurulu Sysmon → "! Sysmon başka bir ayarla çalışıyor"; hizmet yok → Önerilerimiz'e "Davranış bekçisini açın" kartı (düğme `Install-Guard.ps1`'i çalıştırır).

- [ ] **Step 1: Test** — `tests/guard/run.ps1` içine PowerShell testi: `-Mode Lib` ile yüklenip sahte prompt JSON'u `Show-GuardPrompt`'a verildiğinde pencerenin başlığı ve iki düğme metni beklenen; `findings.json`'daki bulgu `Get-StatusSummary().threats` içinde.
- [ ] **Step 2–4: FAIL → uygula → PASS**
- [ ] **Step 5: Commit** — `"guard: tepsi soru penceresi ve panel durumu"`

---

### Task 12: Zararsız test programı ve uçtan uca doğrulama

**Files:**
- Create: `windows/guard/Test/CortmedBehaviorTest.cs`
- Modify: `make-windows-package.ps1` (test programı pakete **eklenmez**; `test/` altına derlenir), `README.md` (test adımları)

**Interfaces:**
- Produces: `CortmedBehaviorTest.exe` — HKCU Run'a `CortmedTest` değeri ekler, `%TEMP%\CortmedFakeDiscord\app-0.0.1\modules\discord_desktop_core-1\discord_desktop_core\index.js` yazar, 60 saniye bekler, çıkarken ikisini de siler. Sınıflandırıcı sahte Discord yolunu da Discord çekirdeği sayar (Task 2 kuralı yol kalıbına bakar).

- [ ] **Step 1: Sandbox'ta uçtan uca** — test programını çalıştır → 5 saniye içinde soru penceresi, nedenler: "Kendini açılışa eklemeye çalıştı.", "Başka bir programın (Discord/tarayıcı) dosyalarını değiştirmeye çalıştı."; "Programı kapat" → süreç yok, Run değeri kaldı ise Tehditler sekmesinde bulgu.
- [ ] **Step 2: Yanlış alarm** — Sandbox'ta Discord, Steam, Chrome kurulumu/güncellemesi → `guard.log`'da Freeze yok.
- [ ] **Step 3: Performans** — 10 dakikalık normal kullanımda `Get-Process CortmedGuard` ortalama CPU < %1, çalışma kümesi < 80 MB.
- [ ] **Step 4: Kullanıcının bilgisayarına kurulum** — paket, Claude dışından (WMI ile başlatılan PowerShell) kurulur; UAC onayını kullanıcı verir.
- [ ] **Step 5: Commit + push** — `"guard: zararsiz davranis test programi ve dogrulama"`
