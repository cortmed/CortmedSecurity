using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Reflection;
using System.Text;
using Cortmed;
using Cortmed.Guard;

[AttributeUsage(AttributeTargets.Method)]
public class TestAttribute : Attribute { }

public static class GuardTests
{
    static string _repoRoot;
    static BehaviorRules _rules;

    public class AssertException : Exception
    {
        public AssertException(string m) : base(m) { }
    }

    public static void Assert(bool cond, string msg = "")
    {
        if (!cond) throw new AssertException(string.IsNullOrEmpty(msg) ? "Assert basarisiz" : msg);
    }

    public static string RepoPath(string relative)
    {
        return Path.Combine(_repoRoot, relative.Replace('/', Path.DirectorySeparatorChar));
    }

    public static BehaviorRules Rules()
    {
        if (_rules == null)
            _rules = BehaviorRules.Parse(File.ReadAllText(RepoPath("engine/rules/behavior_rules.json"), Encoding.UTF8));
        return _rules;
    }

    // ---- testler ----

    [Test] static void RulesParseValuesFromJson()
    {
        var r = BehaviorRules.Parse(File.ReadAllText(RepoPath("engine/rules/behavior_rules.json"), Encoding.UTF8));
        Assert(r.FreezeAt == 80 && r.WarnAt == 50 && r.WindowSeconds == 300);
        Assert(r.Points[Behavior.LsassAccess] == 70 && r.Points[Behavior.Persistence] == 35);
        Assert(r.NeverFreeze.Contains(@"{System32}\lsass.exe") && r.NeverFreeze.Contains(@"{Windows}\explorer.exe"), "tam yol kaliplari");
        Assert(r.Reasons[Behavior.Persistence] == "Kendini açılışa eklemeye çalıştı.");
    }

    // Depodaki kural dosyasi sozluk olarak; testler alan degistirip yeniden ayristirir.
    static Dictionary<string, object> RulesDict()
    {
        return (Dictionary<string, object>)new System.Web.Script.Serialization.JavaScriptSerializer()
            .DeserializeObject(File.ReadAllText(RepoPath("engine/rules/behavior_rules.json"), Encoding.UTF8));
    }

    static string RulesJson(Action<Dictionary<string, object>> change)
    {
        var d = RulesDict();
        change(d);
        return new System.Web.Script.Serialization.JavaScriptSerializer().Serialize(d);
    }

    static bool ParseRejects(Action<Dictionary<string, object>> change)
    {
        string json = RulesJson(change);
        try { BehaviorRules.Parse(json); return false; }
        catch (InvalidDataException) { return true; }
    }

    [Test] static void RulesRejectMissingKeysAndBehaviors()
    {
        foreach (string key in RulesDict().Keys.ToList())
        {
            string k = key;
            Assert(ParseRejects(d => d.Remove(k)), "eksik anahtar reddedilmeli: " + k);
        }
        Assert(ParseRejects(d => ((Dictionary<string, object>)d["points"]).Remove("Injection")), "eksik puan");
        Assert(ParseRejects(d => ((Dictionary<string, object>)d["reasons"]).Remove("MassFileChange")), "eksik neden");
        Assert(ParseRejects(d => ((Dictionary<string, object>)d["reasons"])["Persistence"] = ""), "bos neden");
        Assert(ParseRejects(d => d["neverFreeze"] = new object[] { "csrss.exe" }), "yalniz dosya adi (tam yol degil)");
        Assert(ParseRejects(d => d["trustedImages"] = new object[] { "svchost.exe" }), "guvenilir imaj yalniz ad");
        Assert(ParseRejects(d => d["trustedImages"] = new object[] { @"{Bogus}\a.exe" }), "bilinmeyen belirtec");
    }

    [Test] static void RulesRejectOutOfRangeValues()
    {
        var bad = new List<KeyValuePair<string, int>>
        {
            new KeyValuePair<string, int>("freezeAt", 49), new KeyValuePair<string, int>("freezeAt", 201),
            new KeyValuePair<string, int>("warnAt", 19), new KeyValuePair<string, int>("warnAt", 80),
            new KeyValuePair<string, int>("windowSeconds", 29), new KeyValuePair<string, int>("windowSeconds", 3601),
            new KeyValuePair<string, int>("massFileCount", 9), new KeyValuePair<string, int>("massFileCount", 1001),
            new KeyValuePair<string, int>("massFileSeconds", 0), new KeyValuePair<string, int>("massFileSeconds", 121),
        };
        foreach (var kv in bad)
        {
            var c = kv;
            Assert(ParseRejects(d => d[c.Key] = c.Value), "aralik disi reddedilmeli: " + c.Key + "=" + c.Value);
        }
        Assert(ParseRejects(d => ((Dictionary<string, object>)d["points"])["Injection"] = 201), "puan 201");
        Assert(ParseRejects(d => ((Dictionary<string, object>)d["points"])["Injection"] = -101), "puan -101");
        Assert(ParseRejects(d => d["freezeAt"] = "seksen"), "sayi degil");

        // sinir degerler kabul
        var r = BehaviorRules.Parse(RulesJson(d =>
        {
            d["freezeAt"] = 50; d["warnAt"] = 49; d["windowSeconds"] = 30; d["massFileCount"] = 10; d["massFileSeconds"] = 1;
            ((Dictionary<string, object>)d["points"])["Injection"] = -100;
        }));
        Assert(r.FreezeAt == 50 && r.WarnAt == 49 && r.Points[Behavior.Injection] == -100, "alt sinirlar");
        r = BehaviorRules.Parse(RulesJson(d =>
        {
            d["freezeAt"] = 200; d["warnAt"] = 20; d["windowSeconds"] = 3600; d["massFileCount"] = 1000; d["massFileSeconds"] = 120;
            ((Dictionary<string, object>)d["points"])["Injection"] = 200;
        }));
        Assert(r.FreezeAt == 200 && r.WarnAt == 20 && r.MassFileSeconds == 120, "ust sinirlar");
    }

    [Test] static void RulesRejectUnknownBehaviorName()
    {
        bool threw = false;
        try { BehaviorRules.Parse("{\"points\":{\"Bogus\":5}}"); }
        catch (InvalidDataException) { threw = true; }
        Assert(threw, "bilinmeyen davranis InvalidDataException vermeli");
    }

    // ---- siniflandirici ----

    class Fixture
    {
        public string Name;
        public GuardEvent Event;
        public Behavior? ExpectBehavior;
        public bool PidIsParent;
    }

    static string Str(Dictionary<string, object> d, string k)
    {
        object v;
        return d.TryGetValue(k, out v) && v != null ? Convert.ToString(v) : null;
    }

    static int Int(Dictionary<string, object> d, string k)
    {
        object v;
        return d.TryGetValue(k, out v) && v != null ? Convert.ToInt32(v) : 0;
    }

    static GuardEvent MakeEvent(Dictionary<string, object> d)
    {
        var e = new GuardEvent();
        e.EventId = Int(d, "EventId");
        e.Time = DateTime.UtcNow;
        e.Pid = Int(d, "Pid");
        e.ParentPid = Int(d, "ParentPid");
        e.Image = Str(d, "Image");
        e.ParentImage = Str(d, "ParentImage");
        e.CommandLine = Str(d, "CommandLine");
        e.TargetObject = Str(d, "TargetObject");
        e.TargetFilename = Str(d, "TargetFilename");
        e.TargetPid = Int(d, "TargetPid");
        e.TargetImage = Str(d, "TargetImage");
        e.Hashes = Str(d, "Hashes");
        e.GrantedAccess = Str(d, "GrantedAccess");
        return e;
    }

    static List<Fixture> Fixtures()
    {
        var list = new List<Fixture>();
        var dir = RepoPath("tests/guard/fixtures");
        foreach (var file in Directory.GetFiles(dir, "*.json").OrderBy(f => f, StringComparer.Ordinal))
        {
            var root = (Dictionary<string, object>)new System.Web.Script.Serialization.JavaScriptSerializer()
                .DeserializeObject(File.ReadAllText(file, Encoding.UTF8));
            var f = new Fixture();
            f.Name = Path.GetFileName(file);
            f.Event = MakeEvent((Dictionary<string, object>)root["event"]);
            var ex = (Dictionary<string, object>)root["expect"];
            string b = Str(ex, "behavior");
            if (b != null) f.ExpectBehavior = (Behavior)Enum.Parse(typeof(Behavior), b);
            f.PidIsParent = Str(ex, "pidIs") == "parent";
            list.Add(f);
        }
        return list;
    }

    [Test] static void EachFixtureProducesExpectedBehavior()
    {
        var fixtures = Fixtures();
        Assert(fixtures.Count >= 9, "fixture sayisi");
        foreach (var f in fixtures)
        {
            var hits = new Classifier(Rules()).Classify(f.Event);
            if (f.ExpectBehavior == null) { Assert(hits.Count == 0, f.Name); continue; }
            Assert(hits.Count == 1 && hits[0].Behavior == f.ExpectBehavior.Value, f.Name);
            Assert(hits[0].Pid == (f.PidIsParent ? f.Event.ParentPid : f.Event.Pid), f.Name + " pid");
            Assert(hits[0].Reason == Rules().Reasons[f.ExpectBehavior.Value], f.Name + " reason");
        }
    }

    [Test] static void DiscordUpdaterWritingItsOwnCoreIsNotTamper()
    {
        var e = new GuardEvent();
        e.EventId = 11; e.Pid = 10; e.ParentPid = 1;
        e.Image = @"C:\Users\k\AppData\Local\Discord\Update.exe";
        e.TargetFilename = @"C:\Users\k\AppData\Local\Discord\app-1.0.9\modules\discord_desktop_core-1\discord_desktop_core\index.js";
        Assert(new Classifier(Rules()).Classify(e).Count == 0);
    }

    [Test] static void ChromeWritingExtensionIsNotTamperButOthersAre()
    {
        var e = new GuardEvent();
        e.EventId = 11; e.Pid = 10; e.ParentPid = 1;
        e.TargetFilename = @"C:\Users\k\AppData\Local\Google\Chrome\User Data\Default\Extensions\abc\bg.js";
        e.Image = @"C:\Program Files\Google\Chrome\Application\chrome.exe";
        Assert(new Classifier(Rules()).Classify(e).Count == 0, "chrome");
        e.Image = @"C:\Users\k\Downloads\evil.exe";
        var hits = new Classifier(Rules()).Classify(e);
        Assert(hits.Count == 1 && hits[0].Behavior == Behavior.TamperOtherApp, "evil");
    }

    static List<Hit> Run1(int id, string image, string cmd, string obj, string file, int pid, int target)
    {
        var e = new GuardEvent();
        e.EventId = id; e.Pid = pid; e.ParentPid = pid + 1; e.TargetPid = target;
        e.Image = image; e.CommandLine = cmd; e.TargetObject = obj; e.TargetFilename = file;
        return new Classifier(Rules()).Classify(e);
    }

    const string PS = @"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe";

    [Test] static void EncodingParameterIsNotHiddenScript()
    {
        Assert(Run1(1, PS, "powershell -Command \"x | Out-File -Encoding utf8\"", null, null, 10, 0).Count == 0, "-Encoding");
        Assert(Run1(1, PS, "powershell -ExecutionPolicy Bypass -File a.ps1", null, null, 10, 0).Count == 0, "-ExecutionPolicy");
        Assert(Run1(1, PS, "powershell -w normal a.ps1", null, null, 10, 0).Count == 0, "-w normal");
    }

    [Test] static void EncodedAndHiddenVariantsAreDetected()
    {
        string[] cmds = { "powershell -e AAA", "powershell -EC AAA", "powershell /enc AAA", "powershell -EncodedCommand AAA",
                          "powershell -WindowStyle Hidden a.ps1", "powershell -w hidden a.ps1",
                          "powershell \"[Convert]::FromBase64String('AA')\"" };
        foreach (var c in cmds)
        {
            var h = Run1(1, PS, c, null, null, 10, 0);
            Assert(h.Count == 1 && h[0].Behavior == Behavior.HiddenScript && h[0].Pid == 11, c);
        }
    }

    [Test] static void SchtasksCreateVariants()
    {
        string sch = @"C:\Windows\System32\schtasks.exe";
        Assert(Run1(1, sch, "schtasks /query", null, null, 10, 0).Count == 0, "query");
        var h = Run1(1, sch, "schtasks -create /tn x", null, null, 10, 0);
        Assert(h.Count == 1 && h[0].Behavior == Behavior.Persistence && h[0].Pid == 11, "-create");
    }

    [Test] static void InjectionIntoSelfIsNotHit()
    {
        Assert(Run1(8, @"C:\x\a.exe", null, null, null, 50, 50).Count == 0);
    }

    [Test] static void RunOnceAndUpperCasePathsMatch()
    {
        var h = Run1(13, @"C:\x\a.exe", null, @"HKU\S\Software\Microsoft\Windows\CurrentVersion\RunOnce\x", null, 10, 0);
        Assert(h.Count == 1 && h[0].Behavior == Behavior.Persistence, "runonce");
        h = Run1(13, @"C:\x\a.exe", null, @"HKU\S\SOFTWARE\MICROSOFT\WINDOWS\CURRENTVERSION\RUN\X", null, 10, 0);
        Assert(h.Count == 1 && h[0].Behavior == Behavior.Persistence, "upper run");
        h = Run1(11, @"C:\x\a.exe", null, null, @"C:\U\APPDATA\LOCAL\DISCORD\DISCORD_DESKTOP_CORE\INDEX.JS", 10, 0);
        Assert(h.Count == 1 && h[0].Behavior == Behavior.TamperOtherApp, "upper core");
    }

    [Test] static void FakeDiscordCoreUnderTempFromPowerShellIsTamper()
    {
        var h = Run1(11, PS, null, null,
            @"C:\Users\k\AppData\Local\Temp\CortmedFakeDiscord\app\modules\discord_desktop_core\index.js", 10, 0);
        Assert(h.Count == 1 && h[0].Behavior == Behavior.TamperOtherApp, "fake core");
    }

    [Test] static void TrustedImageMayTouchLsass()
    {
        var e = new GuardEvent();
        e.EventId = 10; e.Pid = 10;
        e.Image = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData), @"Microsoft\Windows Defender\Platform\4.18\MsMpEng.exe");
        e.TargetImage = @"C:\Windows\System32\lsass.exe"; e.TargetPid = 700;
        e.GrantedAccess = "0x1fffff";
        Assert(new Classifier(Rules()).Classify(e).Count == 0, "Defender");
        e.Image = Path.Combine(Environment.SystemDirectory, "svchost.exe");
        Assert(new Classifier(Rules()).Classify(e).Count == 0, "System32 svchost");
    }

    static GuardEvent LsassOpen(string image, string mask)
    {
        var e = new GuardEvent();
        e.EventId = 10; e.Pid = 10; e.Image = image; e.GrantedAccess = mask;
        e.TargetImage = @"C:\Windows\System32\lsass.exe"; e.TargetPid = 700;
        return e;
    }

    [Test] static void LsassAccessNeedsVmReadInGrantedAccess()
    {
        string a = @"C:\Users\x\Downloads\a.exe";
        var c = new Classifier(Rules());
        Assert(c.Classify(LsassOpen(a, "0x1000")).Count == 0, "0x1000 (yalniz sorgu) isabet degil");
        Assert(c.Classify(LsassOpen(a, null)).Count == 0, "maske yok -> isabet degil");
        Assert(c.Classify(LsassOpen(a, "bozuk")).Count == 0, "okunamayan maske -> isabet degil");
        Assert(c.Classify(LsassOpen(a, "0x40")).Count == 0, "0x40 VM_READ icermez");
        foreach (string m in new[] { "0x1010", "0x1410", "0x1fffff", "0x10", "0X143A" })
        {
            var h = c.Classify(LsassOpen(a, m));
            Assert(h.Count == 1 && h[0].Behavior == Behavior.LsassAccess, "isabet olmali: " + m);
        }
    }

    [Test] static void RenamedSvchostInDownloadsOpeningLsassScores()
    {
        var h = new Classifier(Rules()).Classify(LsassOpen(@"C:\Users\x\Downloads\svchost.exe", "0x1010"));
        Assert(h.Count == 1 && h[0].Behavior == Behavior.LsassAccess, "Downloads svchost.exe guvenilir sayilmamali");
        h = new Classifier(Rules()).Classify(LsassOpen(@"C:\Users\x\AppData\Local\Temp\MsMpEng.exe", "0x1010"));
        Assert(h.Count == 1, "Temp MsMpEng.exe guvenilir sayilmamali");
        var sb = new ScoreBoard(Rules());
        Assert(sb.Add(1, 0, h[0], DateTime.Now).Score == Rules().Points[Behavior.LsassAccess], "LSASS puani yazilmali");
    }

    [Test] static void FakeChromeInDownloadsWritingExtensionIsTamper()
    {
        var e = new GuardEvent();
        e.EventId = 11; e.Pid = 10; e.ParentPid = 1;
        e.TargetFilename = @"C:\Users\k\AppData\Local\Google\Chrome\User Data\Default\Extensions\abc\bg.js";
        e.Image = @"C:\Users\k\Downloads\chrome.exe";
        var hits = new Classifier(Rules()).Classify(e);
        Assert(hits.Count == 1 && hits[0].Behavior == Behavior.TamperOtherApp, "sahte chrome.exe");
        e.Image = @"C:\Users\k\AppData\Local\Google\Chrome\Application\chrome.exe";
        Assert(new Classifier(Rules()).Classify(e).Count == 0, "kullanici kurulumu Chrome");
    }

    static GuardEvent RunWrite(string writer, string details)
    {
        var e = new GuardEvent();
        e.EventId = 13; e.Pid = 10; e.Image = writer; e.Details = details;
        e.TargetObject = @"HKU\S-1-5-21-1\Software\Microsoft\Windows\CurrentVersion\Run\App";
        return e;
    }

    [Test] static void SignedAppRefreshingItsOwnRunValueIsNotPersistence()
    {
        string app = @"C:\Users\k\AppData\Local\Vendor\app.exe";
        var signedAll = new Classifier(Rules(), null, p => true);
        Assert(signedAll.Classify(RunWrite(app, "\"C:\\Users\\k\\AppData\\Local\\Vendor\\app.exe\" --minimized")).Count == 0, "kendi klasoru, tirnakli");
        Assert(signedAll.Classify(RunWrite(app, @"C:\Users\k\AppData\Local\Vendor\bin\helper.exe")).Count == 0, "kendi alt klasoru");
        Assert(signedAll.Classify(RunWrite(@"C:\Program Files\Vendor App\app.exe", @"C:\Program Files\Vendor App\app.exe /background")).Count == 0, "bosluklu, tirnaksiz");
        var runOnce = RunWrite(app, app);
        runOnce.TargetObject = @"HKU\S\Software\Microsoft\Windows\CurrentVersion\RunOnce\App";
        Assert(signedAll.Classify(runOnce).Count == 0, "RunOnce");

        Func<List<Hit>, bool> persist = h => h.Count == 1 && h[0].Behavior == Behavior.Persistence;
        Assert(persist(signedAll.Classify(RunWrite(app, @"C:\Users\k\AppData\Local\Temp\x.exe"))), "baska klasore isaret eder");
        Assert(persist(signedAll.Classify(RunWrite(app, @"C:\Users\k\AppData\Local\Vendor2\x.exe"))), "benzer adli klasor");
        Assert(persist(signedAll.Classify(RunWrite(app, @"C:\Users\k\AppData\Local\Vendor\..\Temp\x.exe"))), "..\\ ile kacis");
        Assert(persist(signedAll.Classify(RunWrite(app, @"%LOCALAPPDATA%\Vendor\app.exe"))), "genisletilmemis yol");
        Assert(persist(signedAll.Classify(RunWrite(app, null))), "veri yok");
        Assert(persist(signedAll.Classify(RunWrite(app, @"C:\Windows\System32\rundll32.exe C:\Users\k\AppData\Local\Vendor\x.dll,Run"))), "rundll32 ile");
        Assert(persist(new Classifier(Rules(), null, p => false).Classify(RunWrite(app, app))), "imzasiz yazici");
        Assert(persist(new Classifier(Rules()).Classify(RunWrite(app, app))), "imza denetimi verilmemis");
    }

    [Test] static void SignedSyncClientsDoNotCountDocumentWrites()
    {
        var e = new GuardEvent();
        e.EventId = 11; e.Pid = 10;
        e.TargetFilename = @"C:\Users\k\OneDrive\Desktop\photo1.jpg";
        var signedAll = new Classifier(Rules(), null, p => true);
        foreach (string sc in new[] { @"C:\Users\k\AppData\Local\Microsoft\OneDrive\OneDrive.exe", @"C:\Program Files\Dropbox\Client\Dropbox.exe",
            @"C:\Program Files\Google\Drive File Stream\90.0\GoogleDriveFS.exe", @"C:\Program Files\WindowsApps\AppleInc.iCloud\iCloud\iCloudDrive.exe" })
        {
            e.Image = sc;
            Assert(!signedAll.CountsAsDocumentWrite(e), "imzali esitleme: " + sc);
            Assert(new Classifier(Rules(), null, p => false).CountsAsDocumentWrite(e), "imzasiz ayni ad sayilir: " + sc);
        }
        e.Image = @"C:\Users\k\Downloads\locker.exe";
        Assert(signedAll.CountsAsDocumentWrite(e), "baska imzali program sayilir");
        var none = BehaviorRules.Parse(RulesJson(d => d["syncClients"] = new object[0]));
        e.Image = @"C:\Users\k\AppData\Local\Microsoft\OneDrive\OneDrive.exe";
        Assert(new Classifier(none, null, p => true).CountsAsDocumentWrite(e), "liste imzali kurallardan gelir");
    }

    [Test] static void EngineOneDriveSyncAndOwnRunValueRaiseNothing()
    {
        string dir = NewDataDir();
        var c = new FakeControl(); var s = new FakeSink();
        var g = new GuardEngine(Rules(), dir, c, s);
        string od = @"C:\Users\k\AppData\Local\Microsoft\OneDrive\OneDrive.exe";
        g.SignatureCheck = p => p == od;
        var decisions = new List<Decision>();
        g.DecisionMade = (d, img) => decisions.Add(d);
        var t0 = new DateTime(2026, 10, 29, 10, 0, 0, DateTimeKind.Utc);
        g.OnEvent(new GuardEvent { EventId = 1, Pid = 6000, ParentPid = 900, Image = od, Time = t0 });
        g.OnEvent(new GuardEvent { EventId = 13, Pid = 6000, Image = od, Time = t0.AddSeconds(1),
            TargetObject = @"HKU\S-1-5-21-1\Software\Microsoft\Windows\CurrentVersion\Run\OneDrive", Details = "\"" + od + "\" /background" });
        for (int i = 0; i < 200; i++)
            g.OnEvent(new GuardEvent { EventId = 11, Pid = 6000, Image = od, Time = t0.AddSeconds(2).AddMilliseconds(i * 10),
                TargetFilename = @"C:\Users\k\OneDrive\Masaüstü\klasor\f" + i + ".jpg" });
        Assert(decisions.Count == 0, "esitleme ve kendi Run degeri uyari vermemeli: " + string.Join(",", decisions.Select(d => d.Score + "/" + string.Join(";", d.Reasons))));
        Assert(c.Frozen.Count == 0 && !File.Exists(Path.Combine(dir, "findings.json")), "dondurma/bulgu yok");
    }

    [Test] static void IsDocumentWriteDetectsTurkishFolders()
    {
        var e = new GuardEvent();
        e.EventId = 11;
        foreach (string f in new[] { @"C:\Users\x\OneDrive\Masaüstü\a.docx", @"C:\Users\x\OneDrive\Belgeler\a.docx",
            @"C:\Users\x\OneDrive\Resimler\a.jpg", @"C:\Users\x\OneDrive\Videolar\a.mp4", @"C:\Users\x\OneDrive\Müzik\a.mp3" })
        {
            e.TargetFilename = f;
            Assert(Classifier.IsDocumentWrite(e), f);
        }
    }

    [Test] static void IsDocumentWriteDetectsUserFolders()
    {
        var e = new GuardEvent();
        e.EventId = 11;
        e.TargetFilename = @"C:\Users\k\Documents\a.docx";
        Assert(Classifier.IsDocumentWrite(e), "documents");
        e.TargetFilename = @"C:\Users\k\OneDrive\Desktop\a.docx";
        Assert(Classifier.IsDocumentWrite(e), "desktop");
        e.TargetFilename = @"C:\Users\k\AppData\Local\Temp\a.tmp";
        Assert(!Classifier.IsDocumentWrite(e), "temp");
        e.EventId = 1; e.TargetFilename = @"C:\Users\k\Documents\a.docx";
        Assert(!Classifier.IsDocumentWrite(e), "not event 11");
    }

    // ---- surec agaci / puan tahtasi ----

    static GuardEvent Start(int pid, int ppid, string image)
    {
        var e = new GuardEvent();
        e.EventId = 1; e.Pid = pid; e.ParentPid = ppid; e.Image = image;
        return e;
    }

    static Hit Hit(Behavior b)
    {
        var h = new Hit();
        h.Behavior = b;
        return h;
    }

    [Test] static void RootOfGrandchildIsTopProcess()
    {
        var t = new ProcessTree();
        t.OnProcessStart(Start(10, 1, @"C:\Windows\explorer.exe"));
        t.OnProcessStart(Start(20, 10, @"C:\x\a.exe"));
        t.OnProcessStart(Start(30, 20, @"C:\Windows\System32\cmd.exe"));
        t.OnProcessStart(Start(40, 30, @"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe"));
        Assert(t.RootOf(40) == 20, "powershell -> a");
        Assert(t.RootOf(30) == 20 && t.RootOf(20) == 20, "cmd, a");
        Assert(t.RootOf(999) == 999, "unknown is own root");
        var sub = t.Subtree(20);
        Assert(sub.Count == 3 && sub.Contains(20) && sub.Contains(30) && sub.Contains(40), "subtree");
        Assert(t.ImageOf(30).EndsWith("cmd.exe"), "image");
    }

    static ProcessTree EngineTree()
    {
        return new ProcessTree(img => PathRules.IsRootStarter(img, Rules(), KnownFolders.Current));
    }

    [Test] static void ChildrenOfWindowsHostsStartTheirOwnTree()
    {
        string sys = Environment.SystemDirectory;
        var t = EngineTree();
        t.OnProcessStart(Start(700, 600, Path.Combine(sys, "services.exe")));
        t.OnProcessStart(Start(1000, 700, Path.Combine(sys, "svchost.exe")));
        t.OnProcessStart(Start(1100, 1000, Path.Combine(sys, @"wbem\WmiPrvSE.exe")));
        t.OnProcessStart(Start(1200, 1100, PS));
        t.OnProcessStart(Start(1300, 1000, Path.Combine(sys, "taskhostw.exe")));
        t.OnProcessStart(Start(1310, 1300, @"C:\Program Files\Vendor\tool.exe"));
        Assert(t.RootOf(1000) == 1000, "svchost kendi koku (services cocugu)");
        Assert(t.RootOf(1100) == 1100, "svchost cocugu WmiPrvSE kendi koku");
        Assert(t.RootOf(1200) == 1200, "WmiPrvSE cocugu kendi koku");
        Assert(t.RootOf(1310) == 1310, "taskhostw cocugu kendi koku");
        foreach (string h in new[] { "dllhost.exe", "RuntimeBroker.exe", "sihost.exe", "userinit.exe", "winlogon.exe" })
            Assert(PathRules.IsRootStarter(Path.Combine(sys, h), Rules(), KnownFolders.Current), h);
        Assert(PathRules.IsRootStarter(Path.Combine(Path.GetDirectoryName(sys), @"SysWOW64\dllhost.exe"), Rules(), KnownFolders.Current), "SysWOW64");

        // ayni ad baska klasorde: kok baslatmaz
        t.OnProcessStart(Start(2000, 900, @"C:\Users\k\Downloads\svchost.exe"));
        t.OnProcessStart(Start(2100, 2000, @"C:\Users\k\Downloads\payload.exe"));
        Assert(t.RootOf(2100) == 2000, "sahte svchost'un cocugu onun agacinda kalir");
    }

    [Test] static void ChildrenOfLaunchersStartTheirOwnTree()
    {
        var t = EngineTree();
        t.OnProcessStart(Start(900, 800, @"C:\Windows\explorer.exe"));
        t.OnProcessStart(Start(3000, 900, @"C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe"));
        t.OnProcessStart(Start(3010, 3000, @"C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe"));
        t.OnProcessStart(Start(7000, 3000, @"C:\Users\k\Downloads\CortmedBehaviorTest.exe"));
        Assert(t.RootOf(3000) == 3000 && t.RootOf(7000) == 7000, "Edge'den acilan program kendi koku");
        string[] launchers = { @"C:\Program Files\Google\Chrome\Application\chrome.exe", @"C:\Program Files\Mozilla Firefox\firefox.exe",
            @"C:\Users\k\AppData\Local\Programs\Opera\opera.exe", @"C:\Users\k\AppData\Local\BraveSoftware\Brave-Browser\Application\brave.exe",
            @"C:\Users\k\AppData\Local\Discord\app-1.0.9\Discord.exe", @"C:\Users\k\AppData\Local\Discord\Update.exe",
            @"C:\Program Files\WinRAR\WinRAR.exe", @"C:\Program Files\7-Zip\7zFM.exe", @"C:\Users\k\AppData\Roaming\Telegram Desktop\Telegram.exe",
            @"C:\Users\k\AppData\Local\Microsoft\Teams\current\Teams.exe" };
        int pid = 4000;
        foreach (string l in launchers)
        {
            t.OnProcessStart(Start(pid, 900, l));
            t.OnProcessStart(Start(pid + 1, pid, @"C:\Users\k\Downloads\x.exe"));
            Assert(t.RootOf(pid + 1) == pid + 1, "baslatici: " + l);
            pid += 10;
        }
        // Discord disindaki Update.exe baslatici degildir
        t.OnProcessStart(Start(5000, 900, @"C:\Users\k\AppData\Local\Other\Update.exe"));
        t.OnProcessStart(Start(5001, 5000, @"C:\Users\k\Downloads\x.exe"));
        Assert(t.RootOf(5001) == 5000, "baska Update.exe");
        var noLaunch = BehaviorRules.Parse(RulesJson(d => d["launchers"] = new object[0]));
        Assert(!PathRules.IsRootStarter(launchers[0], noLaunch, KnownFolders.Current), "liste imzali kurallardan gelir");
        Assert(ParseRejects(d => d["launchers"] = new object[] { @"C:\x\a.exe" }), "baslatici: ad ya da \\klasor\\ad.exe");
    }

    [Test] static void ExitedParentDoesNotBreakRootOfChildren()
    {
        var t = new ProcessTree();
        t.OnProcessStart(Start(10, 1, @"C:\Windows\EXPLORER.EXE"));
        t.OnProcessStart(Start(20, 10, @"C:\x\a.exe"));
        t.OnProcessStart(Start(30, 20, @"C:\x\b.exe"));
        t.OnProcessExit(20);
        Assert(t.RootOf(30) == 20, "root survives parent exit");
        t.OnProcessExit(30);
        Assert(t.RootOf(30) == 30, "forgotten after all gone");
    }

    [Test] static void ScoreCrossesFreezeWithBaseAndTwoBehaviors()
    {
        var sb = new ScoreBoard(Rules()); var t = DateTime.Now;
        Assert(sb.Add(100, 30, Hit(Behavior.Persistence), t).Level == DecisionLevel.Warn);
        var d = sb.Add(100, 30, Hit(Behavior.TamperOtherApp), t.AddSeconds(5));
        Assert(d.Level == DecisionLevel.Freeze && d.Reasons.Count == 2 && d.Score == 115, "freeze");
    }

    [Test] static void LowScoreIsLog()
    {
        var sb = new ScoreBoard(Rules());
        var d = sb.Add(1, 0, Hit(Behavior.HiddenScript), DateTime.Now);
        Assert(d.Level == DecisionLevel.Log && d.Score == 30 && d.RootPid == 1);
    }

    [Test] static void HitsOlderThanWindowExpire()
    {
        var sb = new ScoreBoard(Rules()); var t = DateTime.Now;
        sb.Add(100, 0, Hit(Behavior.TamperOtherApp), t);
        var d = sb.Add(100, 0, Hit(Behavior.Persistence), t.AddSeconds(301));
        Assert(d.Score == 35 && d.Reasons.Count == 1 && d.Level == DecisionLevel.Log, "expired");
    }

    [Test] static void SameBehaviorCountsOnce()
    {
        var sb = new ScoreBoard(Rules()); var t = DateTime.Now;
        sb.Add(100, 0, Hit(Behavior.Persistence), t);
        var d = sb.Add(100, 0, Hit(Behavior.Persistence), t.AddSeconds(1));
        Assert(d.Score == 35 && d.Reasons.Count == 1, "once");
    }

    [Test] static void FiftyOneDocumentWritesInTenSecondsIsMassChange()
    {
        var sb = new ScoreBoard(Rules()); var t = DateTime.Now;
        Decision d = null;
        for (int i = 0; i < 50; i++) d = sb.AddDocumentWrite(7, 0, t.AddMilliseconds(i * 100));
        Assert(d.Score == 0 && d.Reasons.Count == 0, "50 is not enough");
        d = sb.AddDocumentWrite(7, 0, t.AddSeconds(6));
        Assert(d.Score == 70 && d.Reasons.Count == 1 && d.Reasons[0] == Rules().Reasons[Behavior.MassFileChange], "51st");
        d = sb.AddDocumentWrite(7, 0, t.AddSeconds(7));
        Assert(d.Score == 70 && d.Reasons.Count == 1, "once per window");
    }

    [Test] static void SlowDocumentWritesAreNotMassChange()
    {
        var sb = new ScoreBoard(Rules()); var t = DateTime.Now;
        Decision d = null;
        for (int i = 0; i < 80; i++) d = sb.AddDocumentWrite(7, 0, t.AddSeconds(i * 2));
        Assert(d.Score == 0, "slow");
    }

    [Test] static void NoSecondFreezeUntilForget()
    {
        var sb = new ScoreBoard(Rules()); var t = DateTime.Now;
        Assert(sb.Add(5, 0, Hit(Behavior.LsassAccess), t).Level == DecisionLevel.Warn);
        Assert(sb.Add(5, 0, Hit(Behavior.DisableProtection), t).Level == DecisionLevel.Freeze, "first freeze");
        var d = sb.Add(5, 0, Hit(Behavior.Injection), t);
        Assert(d.Level != DecisionLevel.Freeze, "no second freeze");
        sb.Forget(5);
        sb.Add(5, 0, Hit(Behavior.LsassAccess), t);
        Assert(sb.Add(5, 0, Hit(Behavior.DisableProtection), t).Level == DecisionLevel.Freeze, "after forget");
    }

    [Test] static void RootEndsOnlyWhenWholeSubtreeExited()
    {
        var t = new ProcessTree();
        t.OnProcessStart(Start(10, 1, @"C:\Windows\explorer.exe"));
        t.OnProcessStart(Start(20, 10, @"C:\x\a.exe"));
        t.OnProcessStart(Start(30, 20, @"C:\x\b.exe"));
        Assert(t.OnProcessExit(20) == 0, "root exits first");
        Assert(t.OnProcessExit(30) == 20, "last child ends root");
        Assert(t.OnProcessExit(999) == 0, "unknown");
    }

    [Test] static void ForgetResetsFrozenSoReusedPidCanFreezeAgain()
    {
        var sb = new ScoreBoard(Rules()); var t = DateTime.Now;
        sb.Add(5, 0, Hit(Behavior.LsassAccess), t);
        Assert(sb.Add(5, 0, Hit(Behavior.DisableProtection), t).Level == DecisionLevel.Freeze);
        sb.Forget(5);
        sb.Add(5, 0, Hit(Behavior.LsassAccess), t.AddSeconds(1000));
        Assert(sb.Add(5, 0, Hit(Behavior.DisableProtection), t.AddSeconds(1000)).Level == DecisionLevel.Freeze);
    }

    [Test] static void IdleStatesAreEvicted()
    {
        var sb = new ScoreBoard(Rules()); var t = DateTime.Now;
        sb.Add(1, 30, Hit(Behavior.Persistence), t);
        Assert(sb.Add(1, 0, null, t.AddSeconds(301)).Score == 0, "evicted, base not remembered");
        sb.Add(2, 30, null, t);
        Assert(sb.Add(2, 0, null, t.AddSeconds(10)).Score == 30, "active kept");
    }

    // ---- dosya guveni ----

    [Test] static void NotepadIsTrusted() { Assert(FileTrust.BaseScore(@"C:\Windows\System32\notepad.exe", Rules()) == -30); }

    [Test] static void SignedInWindowsTempGetsNoBonus() { Assert(FileTrust.LocationScore(@"C:\Windows\Temp\x.exe", true, Rules()) == 0); }

    [Test] static void SignedInLookalikeProgramFilesGetsNoBonus() { Assert(FileTrust.LocationScore(@"C:\Program Files Evil\x.exe", true, Rules()) == 0); }

    [Test] static void SignedInProgramFilesGetsBonus() { Assert(FileTrust.LocationScore(@"C:\Program Files\x\y.exe", true, Rules()) == -30); }

    [Test] static void UnsignedInWindowsTempScoresThirty() { Assert(FileTrust.LocationScore(@"C:\Windows\Temp\x.exe", false, Rules()) == 30); }

    [Test] static void UnsignedInOneDriveDesktopScoresThirty() { Assert(FileTrust.LocationScore(@"C:\Users\x\OneDrive\Desktop\a.exe", false, Rules()) == 30); }

    [Test] static void MissingFileScoresFifteen() { Assert(FileTrust.BaseScore(@"C:\nonexistent\nope.exe", Rules()) == 15); }

    [Test] static void UnsignedExeInTempScoresThirty()
    {
        string exe = Path.Combine(Path.GetTempPath(), "cortmed_unsigned_" + Guid.NewGuid().ToString("N") + ".exe");
        string src = Path.ChangeExtension(exe, ".cs");
        try
        {
            File.WriteAllText(src, "class P { static void Main() { } }");
            string csc = Path.Combine(System.Runtime.InteropServices.RuntimeEnvironment.GetRuntimeDirectory(), "csc.exe");
            var psi = new System.Diagnostics.ProcessStartInfo(csc, "/nologo /out:\"" + exe + "\" \"" + src + "\"");
            psi.UseShellExecute = false; psi.CreateNoWindow = true;
            using (var p = System.Diagnostics.Process.Start(psi)) { p.WaitForExit(); Assert(p.ExitCode == 0, "csc"); }
            Assert(!FileTrust.IsValidlySigned(exe), "unsigned");
            Assert(FileTrust.BaseScore(exe, Rules()) == 30, "score");
        }
        finally
        {
            try { File.Delete(exe); } catch { }
            try { File.Delete(src); } catch { }
        }
    }

    // ---- ProcessControl ----

    static bool AllThreadsSuspended(System.Diagnostics.Process p)
    {
        p.Refresh();
        if (p.Threads.Count == 0) return false;
        foreach (System.Diagnostics.ProcessThread t in p.Threads)
        {
            if (t.ThreadState != System.Diagnostics.ThreadState.Wait ||
                t.WaitReason != System.Diagnostics.ThreadWaitReason.Suspended) return false;
        }
        return true;
    }

    static bool WaitSuspended(System.Diagnostics.Process p, bool expected)
    {
        for (int i = 0; i < 40; i++)
        {
            if (AllThreadsSuspended(p) == expected) return true;
            System.Threading.Thread.Sleep(25);
        }
        return false;
    }

    [Test] static void FreezeAndResumeChildProcess()
    {
        var p = System.Diagnostics.Process.Start(new System.Diagnostics.ProcessStartInfo("powershell", "-NoProfile -Command Start-Sleep 30") { CreateNoWindow = true, UseShellExecute = false });
        try
        {
            System.Threading.Thread.Sleep(1500);
            var frozen = ProcessControl.FreezeTree(new List<int> { p.Id }, Rules());
            Assert(frozen.Count == 1, "dondurulamadi");
            Assert(WaitSuspended(p, true), "thread'ler askida degil");
            ProcessControl.ResumeTree(frozen);
            Assert(WaitSuspended(p, false), "devam etmedi");
            ProcessControl.KillTree(frozen);
            Assert(p.WaitForExit(5000), "kapanmadi");
        }
        finally
        {
            try { if (!p.HasExited) p.Kill(); } catch { }
        }
    }

    [Test] static void ExplorerAndLsassAreNeverFrozen()
    {
        int checkedCount = 0;
        foreach (var name in new[] { "explorer", "lsass" })
        {
            foreach (var pr in System.Diagnostics.Process.GetProcessesByName(name))
            {
                Assert(!ProcessControl.CanFreeze(pr.Id, Rules()), name + " dondurulabilir sayildi");
                checkedCount++;
            }
        }
        Assert(checkedCount > 0, "explorer/lsass bulunamadi");
        Assert(!ProcessControl.CanFreeze(0, Rules()) && !ProcessControl.CanFreeze(4, Rules()), "pid 0/4");
        Assert(!ProcessControl.CanFreeze(System.Diagnostics.Process.GetCurrentProcess().Id, Rules()), "kendi sureci");
    }

    [Test] static void NeverFreezeMatchesFullPathWithHardCodedFloor()
    {
        string sys = Environment.SystemDirectory;
        string win = Path.GetDirectoryName(sys);
        Assert(ProcessControl.CanFreezeImage(@"C:\Users\x\Downloads\csrss.exe", 1, Rules()), "Downloads csrss.exe dondurulabilir");
        Assert(ProcessControl.CanFreezeImage(@"C:\Users\x\AppData\Local\Temp\explorer.exe", 1, Rules()), "Temp explorer.exe dondurulabilir");
        Assert(ProcessControl.CanFreezeImage(@"C:\Users\x\Downloads\cortmedguard.exe", 1, Rules()), "Downloads cortmedguard.exe dondurulabilir");
        // kurallar listeyi bosaltsa bile taban korur
        var empty = BehaviorRules.Parse(RulesJson(d => d["neverFreeze"] = new object[0]));
        string pf = Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles);
        foreach (string p in new[] { Path.Combine(sys, "smss.exe"), Path.Combine(sys, "csrss.exe"), Path.Combine(sys, "wininit.exe"),
            Path.Combine(sys, "winlogon.exe"), Path.Combine(sys, "services.exe"), Path.Combine(sys, "lsass.exe"), Path.Combine(win, "explorer.exe"),
            Path.Combine(sys, "dwm.exe"), Path.Combine(pf, @"Cortmed\CortmedGuard.exe"),
            Path.Combine(Path.GetPathRoot(sys), @"Users\anne\AppData\Local\CortmedSecurity\CortmedSecurity.exe") })
        {
            Assert(!ProcessControl.CanFreezeImage(p, 1, empty), "taban: " + p);
            Assert(!ProcessControl.CanFreezeImage(p.ToUpperInvariant(), 1, Rules()), "kurallar: " + p);
        }
        // imzali kurallar ekleyebilir
        var more = BehaviorRules.Parse(RulesJson(d => d["neverFreeze"] = new object[] { @"{ProgramFiles}\Foo\foo.exe" }));
        Assert(!ProcessControl.CanFreezeImage(Path.Combine(pf, @"Foo\foo.exe"), 1, more), "kuralla eklenen");
        Assert(ProcessControl.CanFreezeImage(Path.Combine(pf, @"Foo\foo.exe"), 1, Rules()), "eklenmemisse dondurulabilir");
        Assert(!ProcessControl.CanFreezeImage("", 1, Rules()) && !ProcessControl.CanFreezeImage(null, 1, Rules()), "yolu bilinmeyen dondurulmaz");
    }

    [Test] static void SessionZeroAndServiceHostsAreNeverFrozen()
    {
        string sys = Environment.SystemDirectory;
        Assert(!ProcessControl.CanFreezeImage(@"C:\Users\x\Downloads\a.exe", 0, Rules()), "oturum 0 dondurulmaz");
        Assert(!ProcessControl.CanFreezeImage(@"C:\Users\x\Downloads\a.exe", -1, Rules()), "oturumu bilinmeyen dondurulmaz");
        Assert(ProcessControl.CanFreezeImage(@"C:\Users\x\Downloads\a.exe", 1, Rules()), "kullanici oturumu dondurulabilir");
        var empty = BehaviorRules.Parse(RulesJson(d => d["neverFreeze"] = new object[0]));
        foreach (string h in new[] { "svchost.exe", @"wbem\WmiPrvSE.exe", "taskhostw.exe", "dllhost.exe", "RuntimeBroker.exe", "sihost.exe" })
            Assert(!ProcessControl.CanFreezeImage(Path.Combine(sys, h), 1, empty), "hizmet sureci: " + h);
        Assert(ProcessControl.CanFreezeImage(@"C:\Users\x\Downloads\svchost.exe", 1, Rules()), "Downloads svchost.exe dondurulabilir");
        // canli: bu bilgisayardaki svchost'lar (oturum 0) asla
        int n = 0;
        foreach (var pr in System.Diagnostics.Process.GetProcessesByName("svchost"))
        {
            Assert(!ProcessControl.CanFreeze(pr.Id, Rules()), "canli svchost " + pr.Id);
            if (++n >= 5) break;
        }
    }

    [Test] static void FromXmlMapsProcessCreateAndRegistryFields()
    {
        var e1 = SysmonReader.FromXml(File.ReadAllText(RepoPath("tests/guard/fixtures/sysmon-event-1.xml"), Encoding.UTF8));
        Assert(e1.EventId == 1 && e1.Pid == 4321 && e1.ParentPid == 1234, "olay 1 pid");
        Assert(e1.Image == @"C:\Users\x\Downloads\oyun.exe" && e1.ParentImage == @"C:\Windows\explorer.exe", "olay 1 imaj");
        Assert(e1.CommandLine.EndsWith("--kur"), "komut satiri");
        Assert(e1.Time.Kind == DateTimeKind.Utc && e1.Time.Year == 2026 && e1.Time.Hour == 10 && e1.Time.Minute == 0, "zaman utc");
        Assert(SysmonReader.Sha256Of(e1.Hashes) == "0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF", "sha256");
        Assert(SysmonReader.Sha256Of(null) == "" && SysmonReader.Sha256Of("MD5=AA") == "", "sha256 bos");
        var e13 = SysmonReader.FromXml(File.ReadAllText(RepoPath("tests/guard/fixtures/sysmon-event-13.xml"), Encoding.UTF8));
        Assert(e13.EventId == 13 && e13.Pid == 4321, "olay 13 pid");
        Assert(e13.TargetObject.EndsWith(@"\Run\Oyun"), "hedef nesne");
        Assert(e13.Details == @"C:\Users\x\Downloads\oyun.exe", "Details (Run degerinin verisi): " + e13.Details);
        Assert(GuardReplay.Parse(new Dictionary<string, object> { { "EventId", 13 }, { "Details", "x" } }).Details == "x", "replay Details");
    }

    [Test] static void FromXmlMapsSourceTargetFieldsForEvent10()
    {
        string xml = "<Event xmlns=\"http://schemas.microsoft.com/win/2004/08/events/event\"><System><EventID>10</EventID><TimeCreated SystemTime=\"2026-10-29T10:00:00.0000000Z\"/></System><EventData>"
            + "<Data Name=\"SourceProcessId\">11</Data><Data Name=\"SourceImage\">C:\\a.exe</Data><Data Name=\"TargetProcessId\">22</Data><Data Name=\"TargetImage\">C:\\Windows\\System32\\lsass.exe</Data>"
            + "<Data Name=\"GrantedAccess\">0x1010</Data></EventData></Event>";
        var e = SysmonReader.FromXml(xml);
        Assert(e.EventId == 10 && e.Pid == 11 && e.TargetPid == 22 && e.Image == @"C:\a.exe" && e.TargetImage.EndsWith("lsass.exe"), "olay 10");
        Assert(e.GrantedAccess == "0x1010", "GrantedAccess: " + e.GrantedAccess);
        var r = GuardReplay.Parse(new Dictionary<string, object> { { "EventId", 10 }, { "GrantedAccess", "0x1410" } });
        Assert(r.GrantedAccess == "0x1410", "replay GrantedAccess");
    }

    [Test] static void SysmonReaderStartOnMissingLogReportsErrorWithoutThrowing()
    {
        var errors = new List<string>();
        using (var r = new SysmonReader(ev => { }, errors.Add))
        {
            bool running = r.IsSysmonRunning();
            bool started = r.Start();
            if (!running)
            {
                Assert(!started && !r.IsWatching, "gunluk yokken Start false donmeli");
                Assert(errors.Count == 1, "onError cagrilmali");
            }
        }
    }

    [Test] static void HandleXmlReportsMalformedXmlAndThrowingCallback()
    {
        var events = new List<GuardEvent>();
        var errors = new List<string>();
        var r = new SysmonReader(events.Add, errors.Add);
        r.HandleXml("<Event><bozuk");
        Assert(errors.Count == 1 && events.Count == 0, "bozuk xml: bir hata, olay yok");

        var ok = File.ReadAllText(RepoPath("tests/guard/fixtures/sysmon-event-1.xml"), Encoding.UTF8);
        r.HandleXml(ok);
        Assert(events.Count == 1 && errors.Count == 1 && events[0].Pid == 4321, "gecerli xml olay uretmeli");

        var errors2 = new List<string>();
        var r2 = new SysmonReader(ev => { throw new InvalidOperationException("patladi"); }, errors2.Add);
        r2.HandleXml(ok);
        Assert(errors2.Count == 1 && errors2[0].Contains("patladi"), "onEvent hatasi bildirilmeli");

        var r3 = new SysmonReader(ev => { throw new InvalidOperationException("x"); }, s => { throw new Exception("y"); });
        r3.HandleXml(ok);
    }

    // ---- pipe ----

    static bool WaitFor(Func<bool> cond, int ms = 5000)
    {
        var sw = System.Diagnostics.Stopwatch.StartNew();
        while (sw.ElapsedMilliseconds < ms)
        {
            if (cond()) return true;
            System.Threading.Thread.Sleep(20);
        }
        return cond();
    }

    [Test]
    static void PromptRoundTripsThroughPipe()
    {
        string name = "CortmedGuardTest-" + Guid.NewGuid().ToString("N");
        var answers = new List<string>();
        using (var server = new GuardPipe(name, (id, d) => { lock (answers) answers.Add(id + "|" + d); return true; }))
        {
            server.Start();
            Assert(!server.HasClient, "istemci yokken HasClient false olmali");
            server.SendPrompt(new Prompt { Id = "dropped" }); // istemci yok: sessizce atilir
            server.SendStatus(true, false);

            using (var client = new GuardClient(name))
            {
                Assert(WaitFor(() => client.Connected), "istemci baglanmali");
                Assert(WaitFor(() => server.HasClient), "sunucu istemciyi gormeli");

                var p = new Prompt
                {
                    Id = "id1", Program = "evil \"x\".exe", Path = @"C:\Users\a\evil.exe",
                    Publisher = "", Score = 77, Reasons = new List<string> { "r1", "r2" }
                };
                server.SendPrompt(p);
                string json = null;
                Assert(WaitFor(() => client.TryDequeuePrompt(out json)), "ask istemciye ulasmali");
                Assert(json.Contains("\"id1\"") && json.Contains("\"ask\"") && json.Contains("77") && json.Contains("r2"), "ask icerigi: " + json);
                Assert(!json.Contains("dropped"), "istemci yokken gonderilen atilmali");

                server.SendStatus(true, true);
                Assert(WaitFor(() => client.SysmonOk && client.SysmonPreexisting), "status istemciye yansimali");
                server.SendStatus(false, false);
                Assert(WaitFor(() => !client.SysmonOk && !client.SysmonPreexisting), "status guncellenmeli");

                client.Answer("id1", "kill");
                Assert(WaitFor(() => { lock (answers) return answers.Contains("id1|kill"); }), "cevap sunucuya ulasmali");
            }
            Assert(WaitFor(() => !server.HasClient), "istemci kapaninca HasClient false olmali");

            // ikinci istemci kabul edilmeli
            using (var client2 = new GuardClient(name))
            {
                Assert(WaitFor(() => client2.Connected && server.HasClient, 12000), "ikinci istemci baglanmali");
                client2.Answer("id2", "allow");
                Assert(WaitFor(() => { lock (answers) return answers.Contains("id2|allow"); }), "ikinci istemcinin cevabi");
            }
        }
        // bagli degilken Answer sessiz olmali
        var lone = new GuardClient("CortmedGuardTest-" + Guid.NewGuid().ToString("N"));
        lone.Answer("x", "kill");
        lone.Dispose();
    }

    [Test]
    static void AnswerGetsResultAndWithdrawReachesClient()
    {
        string name = "CortmedGuardTest-" + Guid.NewGuid().ToString("N");
        using (var server = new GuardPipe(name, (id, d) => id == "known"))
        {
            server.Start();
            Assert(!server.SendWithdraw("none"), "istemci yokken SendWithdraw false");
            using (var client = new GuardClient(name))
            {
                Assert(WaitFor(() => client.Connected && server.HasClient, 12000), "baglanmali");
                Assert(client.Answer("known", "kill"), "bagliyken Answer true (yazildi)");
                string json = null;
                Assert(WaitFor(() => client.TryDequeuePrompt(out json)), "result satiri gelmeli");
                Assert(json.Contains("\"result\"") && json.Contains("\"known\"") && json.Contains("\"ok\":true"), "result ok=true: " + json);
                Assert(client.Answer("nope", "allow"), "bilinmeyen id de yazilir");
                json = null;
                Assert(WaitFor(() => client.TryDequeuePrompt(out json)), "ikinci result gelmeli");
                Assert(json.Contains("\"result\"") && json.Contains("\"nope\"") && json.Contains("\"ok\":false"), "result ok=false: " + json);
                Assert(server.SendWithdraw("w1"), "bagliyken SendWithdraw true");
                json = null;
                Assert(WaitFor(() => client.TryDequeuePrompt(out json)), "withdraw istemciye ulasmali");
                Assert(json.Contains("\"withdraw\"") && json.Contains("\"w1\""), "withdraw satiri: " + json);
            }
        }
        var lone = new GuardClient("CortmedGuardTest-" + Guid.NewGuid().ToString("N"));
        Assert(!lone.Answer("x", "kill"), "bagli degilken Answer false");
        lone.Dispose();
    }

    [Test]
    static void RejectsUnknownIdOversizedAndMalformed()
    {
        string name = "CortmedGuardTest-" + Guid.NewGuid().ToString("N");
        var calls = new List<string>();
        using (var server = new GuardPipe(name, (id, d) =>
        {
            lock (calls) calls.Add(id + "|" + d);
            return id == "known";
        }))
        {
            server.Start();
            using (var raw = new System.IO.Pipes.NamedPipeClientStream(".", name, System.IO.Pipes.PipeDirection.InOut))
            {
                raw.Connect(5000);
                Action<string> send = s =>
                {
                    byte[] b = new UTF8Encoding(false).GetBytes(s);
                    raw.Write(b, 0, b.Length);
                    raw.Flush();
                };
                send("{bozuk\n");
                send(new string('a', 5000) + "\n");
                send("{\"type\":\"answer\",\"id\":\"known\",\"decision\":\"kill\",\"pad\":\"" + new string('b', 5000) + "\"}\n");
                send("{\"type\":\"other\",\"id\":\"bad1\",\"decision\":\"kill\"}\n");
                send("{\"type\":\"answer\",\"id\":\"bad2\",\"decision\":\"KILL\"}\n");
                send("{\"type\":\"answer\",\"id\":\"bad3\",\"decision\":\"delete\"}\n");
                send("{\"type\":\"answer\",\"id\":5,\"decision\":\"kill\"}\n");
                send("{\"type\":\"answer\",\"decision\":\"kill\"}\n");
                send("[1,2]\n");
                send("\n");
                send("{\"type\":\"answer\",\"id\":\"nope\",\"decision\":\"allow\"}\n");
                send("{\"type\":\"answer\",\"id\":\"known\",\"decision\":\"allow\"}\n");

                Assert(WaitFor(() => { lock (calls) return calls.Contains("known|allow"); }), "gecerli cevap sonunda islenmeli");
                lock (calls)
                {
                    Assert(calls.Contains("nope|allow"), "bilinmeyen id onAnswer'a iletilir (false doner)");
                    Assert(calls.Count == 2, "gecersiz satirlar onAnswer'a ulasmamali: " + string.Join(",", calls.ToArray()));
                }
            }
        }
    }

    [Test]
    static void OversizedPromptIsTruncatedAndSendPromptReportsDelivery()
    {
        string name = "CortmedGuardTest-" + Guid.NewGuid().ToString("N");
        using (var server = new GuardPipe(name, (id, d) => true))
        {
            server.Start();
            Assert(!server.SendPrompt(new Prompt { Id = "none" }), "istemci yokken SendPrompt false olmali");
            using (var client = new GuardClient(name))
            {
                Assert(WaitFor(() => client.Connected && server.HasClient), "baglanmali");
                var reasons = new List<string>();
                for (int i = 0; i < 20; i++) reasons.Add("<>&' \u015f\u011f\u00fc\u0130\u0131\u00f6\u00e7 " + new string('x', 400));
                var p = new Prompt
                {
                    Id = "big1", Program = new string('p', 3000), Path = "C:\\" + new string('\u015f', 10000),
                    Publisher = new string('<', 2000), Score = 90, Reasons = reasons
                };
                Assert(server.SendPrompt(p), "SendPrompt baglayken true donmeli");
                string json = null;
                Assert(WaitFor(() => client.TryDequeuePrompt(out json)), "buyuk istem istemciye ulasmali");
                Assert(json.Contains("\"big1\""), "id korunmali");
                Assert(Encoding.UTF8.GetByteCount(json) < 4096, "satir 4096 baytin altinda olmali");
            }
            Assert(WaitFor(() => !server.HasClient), "istemci kapandi");
            Assert(!server.SendPrompt(new Prompt { Id = "after" }), "kopan istemciye false");
        }
    }

    [Test]
    static void ClientToMissingPipeIdlesAndStatusResetsOnDisconnect()
    {
        string missing = "CortmedGuardTest-" + Guid.NewGuid().ToString("N");
        var proc = System.Diagnostics.Process.GetCurrentProcess();
        TimeSpan before = proc.TotalProcessorTime;
        using (var c = new GuardClient(missing))
        {
            System.Threading.Thread.Sleep(3000);
            Assert(!c.Connected, "olmayan boruya baglanmamali");
            Assert(c.ConnectAttempts == 0, "boru yokken Connect denenmemeli: " + c.ConnectAttempts);
        }
        proc.Refresh();
        double cpu = (proc.TotalProcessorTime - before).TotalMilliseconds;
        Assert(cpu < 300, "bosta CPU kullanimi: " + cpu + " ms");

        string name = "CortmedGuardTest-" + Guid.NewGuid().ToString("N");
        using (var client = new GuardClient(name))
        {
            using (var server = new GuardPipe(name, (id, d) => true))
            {
                server.Start();
                Assert(WaitFor(() => client.Connected && server.HasClient, 12000), "baglanmali");
                server.SendStatus(true, true);
                Assert(WaitFor(() => client.SysmonOk && client.SysmonPreexisting), "status gelmeli");
            }
            Assert(WaitFor(() => !client.Connected), "kopma algilanmali");
            Assert(!client.SysmonOk && !client.SysmonPreexisting, "kopunca status sifirlanmali");
        }
    }

    // ---- hizmet motoru ----

    const string EvilHash = "9F86D081884C7D659A2FEAA0C55AD015A3BF4F1B2B0B822CD15D6C15B0F00A08";

    class FakeControl : IProcessControl
    {
        public List<List<int>> Frozen = new List<List<int>>();
        public List<List<int>> Resumed = new List<List<int>>();
        public List<List<int>> Killed = new List<List<int>>();
        public Dictionary<int, long> Starts = new Dictionary<int, long>();
        public HashSet<int> Unfreezable = new HashSet<int>();
        public List<int> FreezeTree(List<int> pids)
        {
            Frozen.Add(new List<int>(pids));
            return pids.Where(p => !Unfreezable.Contains(p)).ToList();
        }
        public void ResumeTree(List<int> pids) { Resumed.Add(new List<int>(pids)); }
        public void KillTree(List<int> pids) { Killed.Add(new List<int>(pids)); }
        public long StartTimeOf(int pid)
        {
            long v;
            return Starts.TryGetValue(pid, out v) ? v : 1000L + pid;
        }
    }

    class FakeSink : IPromptSink
    {
        public bool Client = true;
        public List<Prompt> Sent = new List<Prompt>();
        public bool HasClient { get { return Client; } }
        public bool Send(Prompt p)
        {
            if (!Client) return false;
            Sent.Add(p);
            return true;
        }
        public List<string> Withdrawn = new List<string>();
        public object EngineLock;          // verilirse Withdraw'in _lock altinda cagrilip cagrilmadigi kaydedilir
        public bool WithdrawUnderLock;
        public bool Withdraw(string id)
        {
            if (EngineLock != null && System.Threading.Monitor.IsEntered(EngineLock)) WithdrawUnderLock = true;
            Withdrawn.Add(id);
            return Client;
        }
    }

    static string NewDataDir()
    {
        string d = Path.Combine(Path.GetTempPath(), "CortmedGuardTest-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(d);
        return d;
    }

    static void RunReplay(GuardEngine engine)
    {
        foreach (var e in GuardReplay.LoadEvents(RepoPath("tests/guard/replay"))) engine.OnEvent(e);
    }

    static string ReadData(string dir, string name)
    {
        string p = Path.Combine(dir, name);
        return File.Exists(p) ? File.ReadAllText(p, Encoding.UTF8) : "";
    }

    static GuardEvent Start(int pid, int parent, string image, int sec)
    {
        return new GuardEvent
        {
            EventId = 1, Pid = pid, ParentPid = parent, Image = image,
            Time = new DateTime(2026, 10, 29, 10, 0, sec, DateTimeKind.Utc)
        };
    }

    [Test] static void ReplayLoadsEventsInFilenameOrder()
    {
        var evs = GuardReplay.LoadEvents(RepoPath("tests/guard/replay"));
        Assert(evs.Count == 4, "olay sayisi " + evs.Count);
        Assert(evs[0].EventId == 1 && evs[0].Pid == 5000 && evs[3].EventId == 11, "sira");
        Assert(evs[0].Time == new DateTime(2026, 10, 29, 10, 0, 0, DateTimeKind.Utc) && evs[0].Time.Kind == DateTimeKind.Utc, "zaman UTC");
        Assert(SysmonReader.Sha256Of(evs[0].Hashes) == EvilHash, "hash");
    }

    [Test] static void ReplayPersistencePlusTamperFreezesAndAsks()
    {
        string dir = NewDataDir();
        var c = new FakeControl(); var s = new FakeSink();
        var g = new GuardEngine(Rules(), dir, c, s);
        RunReplay(g);
        Assert(c.Frozen.Count == 1, "FreezeTree bir kez: " + c.Frozen.Count);
        Assert(c.Frozen[0].Count == 2 && c.Frozen[0][0] == 5000 && c.Frozen[0][1] == 5001, "kok once, cocuk sonra");
        Assert(s.Sent.Count == 1, "bir soru gonderilmeli");
        var p = s.Sent[0];
        Assert(p.Reasons.Count == 2 && p.Score == 100 && p.Program == "evil.exe", "soru icerigi");
        Assert(p.Path.EndsWith("\\Temp\\evil.exe") && !string.IsNullOrEmpty(p.Id), "yol/id");
        Assert(ReadData(dir, "pending.json").Contains(p.Id), "pending.json'a yazilmali");
        string findings = ReadData(dir, "findings.json");
        Assert(findings.Contains("YELLOW") && findings.Contains("behavior:" + EvilHash), "50 puanda Warn bulgusu");
        Assert(ReadData(dir, "guard.log").Length > 0, "guard.log yazilmali");
    }

    [Test] static void ReplayTestProgramFromEdgeFreezesTheProgramNotEdge()
    {
        string dir = NewDataDir();
        var c = new FakeControl(); var s = new FakeSink();
        var g = new GuardEngine(Rules(), dir, c, s);
        var decisions = new List<Decision>();
        g.DecisionMade = (d, img) => decisions.Add(d);
        foreach (var e in GuardReplay.LoadEvents(RepoPath("tests/guard/fixtures/behavior-test-edge"))) g.OnEvent(e);
        Assert(c.Frozen.Count == 1, "bir dondurma: " + c.Frozen.Count);
        Assert(c.Frozen[0].Count == 1 && c.Frozen[0][0] == 7000, "yalnizca deneme programi: " + string.Join(",", c.Frozen[0]));
        Assert(decisions.All(d => d.RootPid == 7000), "tum kararlar programin kokunde");
        Assert(decisions.Any(d => d.Level == DecisionLevel.Freeze && d.Score >= 80 && d.Reasons.Count == 2), "Freeze, iki neden");
        Assert(s.Sent.Count == 1 && s.Sent[0].Program == "CortmedBehaviorTest.exe" && s.Sent[0].Path.EndsWith(@"\Downloads\CortmedBehaviorTest.exe"), "soru programi adlandirir");
        string findings = ReadData(dir, "findings.json");
        Assert(findings.Contains("CortmedBehaviorTest.exe") && !findings.Contains("msedge"), "bulgu programi adlandirir: " + findings);
        Assert(!ReadData(dir, "pending.json").Contains("msedge"), "bekleyen soru Edge'i adlandirmaz");
    }

    [Test] static void ReplaySvchostRootIsNeverFrozenAndWmiChildrenAreOwnRoots()
    {
        string dir = NewDataDir();
        var c = new FakeControl(); var s = new FakeSink();
        var g = new GuardEngine(Rules(), dir, c, s);
        var decisions = new List<Decision>();
        g.DecisionMade = (d, img) => decisions.Add(d);
        foreach (var e in GuardReplay.LoadEvents(RepoPath("tests/guard/fixtures/svchost-wmi"))) g.OnEvent(e);
        Assert(decisions.Any(d => d.RootPid == 1000 && d.Level == DecisionLevel.Freeze), "svchost'un kendi davranislari esigi asar");
        Assert(decisions.All(d => d.RootPid == 1000), "WMI ve PowerShell cocuklari svchost'a puan yazmaz: "
            + string.Join(",", decisions.Select(d => d.RootPid + "/" + d.Score)));
        Assert(!c.Frozen.Any(l => l.Contains(1000) || l.Contains(1100) || l.Contains(1200)), "svchost agaci dondurulmamali");
        Assert(s.Sent.Count == 0 && !ReadData(dir, "pending.json").Contains("svchost"), "soru yok");
        string findings = ReadData(dir, "findings.json");
        Assert(findings.Contains("svchost.exe") && findings.Contains("dondurulamad"), "dondurulamadi bulgusu: " + findings);
    }

    [Test] static void KillAnswerKillsTreeAndRecordsFinding()
    {
        string dir = NewDataDir();
        var c = new FakeControl(); var s = new FakeSink();
        var g = new GuardEngine(Rules(), dir, c, s);
        RunReplay(g);
        string id = s.Sent[0].Id;
        Assert(!g.OnAnswer("bilinmeyen", "kill"), "bilinmeyen id reddedilmeli");
        Assert(!g.OnAnswer(id, "sil"), "gecersiz karar reddedilmeli");
        Assert(g.OnAnswer(id, "kill"), "kill kabul edilmeli");
        Assert(c.Killed.Count == 1 && c.Killed[0].SequenceEqual(new[] { 5000, 5001 }), "agac kok once kapatilmali");
        Assert(c.Resumed.Count == 0, "devam ettirilmemeli");
        Assert(!g.OnAnswer(id, "kill"), "ikinci cevap reddedilmeli");
        Assert(!ReadData(dir, "pending.json").Contains(id), "pending'den silinmeli");
        var list = (object[])new System.Web.Script.Serialization.JavaScriptSerializer().DeserializeObject(ReadData(dir, "findings.json"));
        Assert(list.Length == 1, "ayni anahtar tek bulgu: " + list.Length);
        var f = (Dictionary<string, object>)list[0];
        Assert((string)f["level"] == "RED" && (string)f["key"] == "behavior:" + EvilHash && (string)f["tab"] == "threat", "RED bulgu");
        Assert(((string)f["title"]).Contains("evil.exe") && ((string)f["report"]).Contains("100"), "baslik/rapor");
        Assert(!File.Exists(Path.Combine(dir, "allowed.txt")) || !ReadData(dir, "allowed.txt").Contains(EvilHash), "kill izin listesine eklemez");
    }

    [Test] static void KillSkipsPidsWhoseStartTimeChanged()
    {
        string dir = NewDataDir();
        var c = new FakeControl(); var s = new FakeSink();
        var g = new GuardEngine(Rules(), dir, c, s);
        RunReplay(g);
        c.Starts[5001] = 42; // pid yeniden kullanildi
        Assert(g.OnAnswer(s.Sent[0].Id, "kill"));
        Assert(c.Killed.Count == 1 && c.Killed[0].SequenceEqual(new[] { 5000 }), "degisen pid kapatilmamali");
    }

    [Test] static void AllowAnswerResumesAndPersistsHash()
    {
        string dir = NewDataDir();
        var c = new FakeControl(); var s = new FakeSink();
        var g = new GuardEngine(Rules(), dir, c, s);
        RunReplay(g);
        Assert(g.OnAnswer(s.Sent[0].Id, "allow"), "allow kabul edilmeli");
        Assert(c.Resumed.Count == 1 && c.Resumed[0].SequenceEqual(new[] { 5000, 5001 }), "agac devam etmeli");
        Assert(c.Killed.Count == 0, "kapatilmamali");
        Assert(ReadData(dir, "allowed.txt").Split(new[] { '\r', '\n' }, StringSplitOptions.RemoveEmptyEntries).Contains(EvilHash), "hash allowed.txt'te");
        // Forget sonrasi ayni kokten yeni davranis tekrar sorulmamali (izinli)
        var e = new GuardEvent { EventId = 13, Pid = 5000, Image = @"C:\Users\k\AppData\Local\Temp\evil.exe",
            TargetObject = @"HKU\S-1-5-21-1\Software\Microsoft\Windows\CurrentVersion\Run\X", Time = new DateTime(2026, 10, 29, 10, 1, 0, DateTimeKind.Utc) };
        g.OnEvent(e);
        e = new GuardEvent { EventId = 8, Pid = 5000, TargetPid = 77, Image = @"C:\Users\k\AppData\Local\Temp\evil.exe", Time = new DateTime(2026, 10, 29, 10, 1, 1, DateTimeKind.Utc) };
        g.OnEvent(e);
        Assert(c.Frozen.Count == 1 && s.Sent.Count == 1, "izinli program yeniden dondurulmamali");
    }

    [Test] static void AllowedHashIsNotAskedAgainAfterRestart()
    {
        string dir = NewDataDir();
        var c = new FakeControl(); var s = new FakeSink();
        var g = new GuardEngine(Rules(), dir, c, s);
        RunReplay(g);
        Assert(g.OnAnswer(s.Sent[0].Id, "allow"));
        var c2 = new FakeControl(); var s2 = new FakeSink();
        var g2 = new GuardEngine(Rules(), dir, c2, s2);
        RunReplay(g2);
        Assert(c2.Frozen.Count == 0 && s2.Sent.Count == 0, "izinli hash tekrar dondurulmamali");
    }

    [Test] static void PendingPromptsAreReplayedOnConnect()
    {
        string dir = NewDataDir();
        var c = new FakeControl(); var s = new FakeSink();
        s.Client = false;
        var g = new GuardEngine(Rules(), dir, c, s);
        RunReplay(g);
        Assert(c.Frozen.Count == 1 && s.Sent.Count == 0, "tepsi yokken dondur, gonderme");
        s.Client = true;
        g.OnClientConnected();
        Assert(s.Sent.Count == 1, "baglaninca gonderilmeli");
        g.OnClientConnected();
        Assert(s.Sent.Count == 2, "yeni baglantida bekleyen soru yeniden gonderilmeli");
        Assert(g.OnAnswer(s.Sent[0].Id, "kill"));
        g.OnClientConnected();
        Assert(s.Sent.Count == 2, "cevaplanan soru gonderilmemeli");
    }

    [Test] static void PendingSurvivesRestartAndDropsGoneProcesses()
    {
        string dir = NewDataDir();
        var c = new FakeControl(); var s = new FakeSink();
        s.Client = false;
        var g = new GuardEngine(Rules(), dir, c, s);
        RunReplay(g);
        // yeniden baslama: surecler hala ayni
        var c2 = new FakeControl(); var s2 = new FakeSink();
        var g2 = new GuardEngine(Rules(), dir, c2, s2);
        g2.OnClientConnected();
        Assert(s2.Sent.Count == 1 && s2.Sent[0].Reasons.Count == 2 && s2.Sent[0].Score == 100, "bekleyen soru geri yuklenmeli");
        Assert(g2.OnAnswer(s2.Sent[0].Id, "kill"));
        Assert(c2.Killed.Count == 1 && c2.Killed[0].SequenceEqual(new[] { 5000, 5001 }), "geri yuklenen agac kapatilmali");

        // surecler yok olduysa kayit atilir
        string dir2 = NewDataDir();
        var c3 = new FakeControl(); var s3 = new FakeSink(); s3.Client = false;
        RunReplay(new GuardEngine(Rules(), dir2, c3, s3));
        var c4 = new FakeControl(); c4.Starts[5000] = 0; c4.Starts[5001] = 9;
        var s4 = new FakeSink();
        var g4 = new GuardEngine(Rules(), dir2, c4, s4);
        g4.OnClientConnected();
        Assert(s4.Sent.Count == 0, "biten sureclerin sorusu atilmali");
        Assert(!ReadData(dir2, "pending.json").Contains("evil.exe"), "pending.json temizlenmeli");
    }

    [Test] static void ChildStartedDuringFreezeIsSuspended()
    {
        string dir = NewDataDir();
        var c = new FakeControl(); var s = new FakeSink();
        var g = new GuardEngine(Rules(), dir, c, s);
        RunReplay(g);
        g.OnEvent(Start(5002, 5001, @"C:\Windows\System32\cmd.exe", 10));
        Assert(c.Frozen.Count == 2 && c.Frozen[1].SequenceEqual(new[] { 5002 }), "yeni cocuk hemen dondurulmali");
        Assert(s.Sent.Count == 1, "yeni soru yok");
        Assert(g.OnAnswer(s.Sent[0].Id, "kill"));
        Assert(c.Killed[0].SequenceEqual(new[] { 5000, 5001, 5002 }), "yeni cocuk da kapatilmali");
    }

    [Test] static void ReusedRootPidIsNotTreatedAsFrozenTree()
    {
        string dir = NewDataDir();
        var c = new FakeControl(); var s = new FakeSink();
        var g = new GuardEngine(Rules(), dir, c, s);
        RunReplay(g);
        // 5000 olu, pid baska bir kok surece verildi; onun cocugu dondurulmamali
        g.OnEvent(new GuardEvent { EventId = 5, Pid = 5000, Time = new DateTime(2026, 10, 29, 10, 0, 20, DateTimeKind.Utc) });
        g.OnEvent(Start(5000, 900, @"C:\Windows\System32\notepad.exe", 21));
        g.OnEvent(Start(5003, 5000, @"C:\Windows\System32\cmd.exe", 22));
        Assert(c.Frozen.Count == 1, "yeniden kullanilan kokun cocugu dondurulmamali: " + c.Frozen.Count);
        Assert(g.OnAnswer(s.Sent[0].Id, "allow"), "eski soru hala cevaplanabilir");
    }

    [Test] static void WholeTreeExitDropsPendingPrompt()
    {
        string dir = NewDataDir();
        var c = new FakeControl(); var s = new FakeSink();
        var g = new GuardEngine(Rules(), dir, c, s);
        RunReplay(g);
        g.OnEvent(new GuardEvent { EventId = 5, Pid = 5001, Time = new DateTime(2026, 10, 29, 10, 0, 30, DateTimeKind.Utc) });
        g.OnEvent(new GuardEvent { EventId = 5, Pid = 5000, Time = new DateTime(2026, 10, 29, 10, 0, 31, DateTimeKind.Utc) });
        Assert(!g.OnAnswer(s.Sent[0].Id, "kill"), "agac bitince soru dusmeli");
        Assert(c.Killed.Count == 0);
    }

    [Test] static void TreeExitWithdrawsPromptOnceOutsideLock()
    {
        string dir = NewDataDir();
        var c = new FakeControl(); var s = new FakeSink();
        var g = new GuardEngine(Rules(), dir, c, s);
        s.EngineLock = typeof(GuardEngine).GetField("_lock", BindingFlags.NonPublic | BindingFlags.Instance).GetValue(g);
        RunReplay(g);
        string id = s.Sent[0].Id;
        Assert(s.Withdrawn.Count == 0, "agac yasarken geri cekme yok");
        g.OnEvent(new GuardEvent { EventId = 5, Pid = 5001, Time = new DateTime(2026, 10, 29, 10, 0, 30, DateTimeKind.Utc) });
        Assert(s.Withdrawn.Count == 0, "cocuk bitince agac hala var");
        g.OnEvent(new GuardEvent { EventId = 5, Pid = 5000, Time = new DateTime(2026, 10, 29, 10, 0, 31, DateTimeKind.Utc) });
        Assert(s.Withdrawn.Count == 1 && s.Withdrawn[0] == id, "tam bir geri cekme: " + string.Join(",", s.Withdrawn.ToArray()));
        Assert(!s.WithdrawUnderLock, "Withdraw _lock altinda cagrilmamali");
        g.OnEvent(new GuardEvent { EventId = 5, Pid = 5000, Time = new DateTime(2026, 10, 29, 10, 0, 32, DateTimeKind.Utc) });
        Assert(s.Withdrawn.Count == 1, "ikinci kez geri cekilmez");
    }

    [Test] static void FindingHasUtcTime()
    {
        string dir = NewDataDir();
        var c = new FakeControl(); var s = new FakeSink();
        var g = new GuardEngine(Rules(), dir, c, s);
        RunReplay(g);
        var list = (object[])new System.Web.Script.Serialization.JavaScriptSerializer().DeserializeObject(ReadData(dir, "findings.json"));
        var f = (Dictionary<string, object>)list[0];
        object t;
        DateTime parsed;
        Assert(f.TryGetValue("time", out t) && DateTime.TryParse((string)t, System.Globalization.CultureInfo.InvariantCulture,
            System.Globalization.DateTimeStyles.RoundtripKind, out parsed) && parsed.Kind == DateTimeKind.Utc, "time UTC ISO 8601: " + t);
    }

    [Test] static void NothingFrozenRecordsWarnInsteadOfPrompt()
    {
        string dir = NewDataDir();
        var c = new FakeControl(); var s = new FakeSink();
        c.Unfreezable.Add(5000); c.Unfreezable.Add(5001);
        var g = new GuardEngine(Rules(), dir, c, s);
        RunReplay(g);
        Assert(c.Frozen.Count == 1 && s.Sent.Count == 0, "soru olmamali");
        Assert(!ReadData(dir, "pending.json").Contains("evil.exe"), "pending olmamali");
        string findings = ReadData(dir, "findings.json");
        Assert(findings.Contains("YELLOW") && findings.Contains("dondurulamad"), "Warn bulgusu: " + findings);
    }

    [Test] static void FindingsKeepAtMost200Newest()
    {
        string dir = NewDataDir();
        string file = Path.Combine(dir, "findings.json");
        for (int i = 0; i < 205; i++)
        {
            var f = new Dictionary<string, object>();
            f["key"] = "k" + i; f["level"] = "YELLOW"; f["title"] = "t"; f["detail"] = "d"; f["path"] = ""; f["tab"] = "threat"; f["report"] = "r";
            FindingStore.Upsert(file, f);
        }
        var list = FindingStore.Read(file);
        Assert(list.Count == 200 && (string)list[0]["key"] == "k204", "en yeni 200: " + list.Count);
        Assert(!list.Any(x => (string)x["key"] == "k0"), "en eski atilmali");
    }

    [Test] static void GuardLogRotatesAtOneMegabyte()
    {
        string dir = NewDataDir();
        string path = Path.Combine(dir, "guard.log");
        File.WriteAllText(path, new string('x', 1024 * 1024 + 10));
        var log = new GuardLog(path);
        log.Write("satir\r\nenjeksiyon");
        Assert(File.Exists(path + ".1") && new FileInfo(path + ".1").Length > 1024 * 1024, "eski kayit .1 olmali");
        string text = File.ReadAllText(path, Encoding.UTF8);
        Assert(text.Contains("satir enjeksiyon") && text.Split('\n').Length == 2, "tek satir: " + text);
    }

    static string PendingEntry(string id, int pid, string start)
    {
        return "{\"id\":\"" + id + "\",\"root\":" + pid + ",\"hash\":\"\",\"program\":\"" + id + ".exe\",\"path\":\"C:\\\\x\\\\" + id
            + ".exe\",\"publisher\":\"\",\"score\":90,\"reasons\":[\"r\"],\"pids\":[" + pid + "],\"starts\":[\"" + start + "\"]}";
    }

    [Test] static void CorruptPendingEntryDoesNotDiscardOthers()
    {
        string dir = NewDataDir();
        string path = Path.Combine(dir, "pending.json");
        // FakeControl varsayilan baslangic zamani: 1000 + pid
        File.WriteAllText(path, "[" + PendingEntry("good1", 7000, "8000") + ",42," + PendingEntry("bad", 7100, "x-not-a-number") + ","
            + "{\"id\":\"bad2\",\"pids\":\"7200\"}," + PendingEntry("good2", 7300, "8300") + "]");
        var c = new FakeControl(); var s = new FakeSink();
        var g = new GuardEngine(Rules(), dir, c, s);
        Assert(g.PendingCount == 2, "iki iyi kayit geri yuklenmeli: " + g.PendingCount);
        string text = ReadData(dir, "pending.json");
        Assert(text.Contains("good1") && text.Contains("good2"), "iyi kayitlar dosyada kalmali: " + text);
        Assert(File.Exists(path + ".bad") && ReadData(dir, "pending.json.bad").Contains("x-not-a-number"), "ozgun dosya .bad olarak yedeklenmeli");
        Assert(ReadData(dir, "guard.log").Contains("bozuk"), "bozuk kayit loglanmali");
        g.OnClientConnected();
        Assert(s.Sent.Count == 2, "iki soru gonderilmeli");
        // yeniden baslama: hala iki kayit
        Assert(new GuardEngine(Rules(), dir, new FakeControl(), new FakeSink()).PendingCount == 2, "yeniden yuklemede iki kayit");
    }

    [Test] static void UnparseablePendingFileIsMovedToBad()
    {
        string dir = NewDataDir();
        string path = Path.Combine(dir, "pending.json");
        File.WriteAllText(path, "{{{ bozuk json");
        var c = new FakeControl(); var s = new FakeSink();
        var g = new GuardEngine(Rules(), dir, c, s);
        Assert(g.PendingCount == 0, "kayit yok");
        Assert(!File.Exists(path), "pending.json bos kayitla ezilmemeli");
        Assert(ReadData(dir, "pending.json.bad") == "{{{ bozuk json", ".bad'e tasinmali");
        RunReplay(g);
        Assert(c.Frozen.Count == 1 && s.Sent.Count == 1, "motor calismaya devam etmeli");
    }

    [Test] static void RepeatedWarnAtSameScoreWritesOnce()
    {
        string dir = NewDataDir();
        var c = new FakeControl(); var s = new FakeSink();
        var g = new GuardEngine(BehaviorRules.Parse(Encoding.UTF8.GetString(RulesBytes(200))), dir, c, s);
        string evil = @"C:\Users\k\AppData\Local\Temp\evil.exe";
        g.OnEvent(Start(5000, 900, evil, 0));
        g.OnEvent(new GuardEvent { EventId = 13, Pid = 5000, Image = evil, Time = new DateTime(2026, 10, 29, 10, 0, 1, DateTimeKind.Utc),
            TargetObject = @"HKU\S-1-5-21-1\Software\Microsoft\Windows\CurrentVersion\Run\X" });
        string findings = Path.Combine(dir, "findings.json");
        Assert(File.Exists(findings), "ilk Warn bulgu yazmali");
        File.Delete(findings);
        for (int i = 0; i < 20; i++)
            g.OnEvent(new GuardEvent { EventId = 11, Pid = 5000, Image = evil, TargetFilename = @"C:\Users\k\Documents\f" + i + ".docx",
                Time = new DateTime(2026, 10, 29, 10, 0, 2, DateTimeKind.Utc) });
        Assert(!File.Exists(findings), "ayni puanda findings.json yeniden yazilmamali");
        Func<int> warnLines = () => ReadData(dir, "guard.log").Split('\n').Count(l => l.Contains("Şüpheli davranış"));
        Assert(warnLines() == 1, "tek Warn kayit satiri: " + warnLines());
        g.OnEvent(new GuardEvent { EventId = 1, Pid = 5005, ParentPid = 5000, Image = @"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
            CommandLine = "powershell -enc AAAA", Time = new DateTime(2026, 10, 29, 10, 0, 3, DateTimeKind.Utc) });
        Assert(File.Exists(findings) && warnLines() == 2, "puan artinca yeniden yazilmali: " + warnLines());
        Assert(c.Frozen.Count == 0, "dondurma yok");
    }

    static void SystemToolTree(GuardEngine g, int pid, int sec)
    {
        string img = @"C:\Windows\System32\wscript.exe";
        g.OnEvent(new GuardEvent { EventId = 1, Pid = pid, ParentPid = 900, Image = img, Hashes = "SHA256=" + new string('B', 64),
            Time = new DateTime(2026, 10, 29, 10, 0, sec, DateTimeKind.Utc) });
        g.OnEvent(new GuardEvent { EventId = 13, Pid = pid, Image = img, Time = new DateTime(2026, 10, 29, 10, 0, sec + 1, DateTimeKind.Utc),
            TargetObject = @"HKU\S-1-5-21-1\Software\Microsoft\Windows\CurrentVersion\Run\X" });
        g.OnEvent(new GuardEvent { EventId = 11, Pid = pid, Image = img, Time = new DateTime(2026, 10, 29, 10, 0, sec + 2, DateTimeKind.Utc),
            TargetFilename = @"C:\Users\k\AppData\Local\Discord\app-1.0.9\modules\discord_desktop_core-1\discord_desktop_core\index.js" });
        g.OnEvent(new GuardEvent { EventId = 13, Pid = pid, Image = img, Time = new DateTime(2026, 10, 29, 10, 0, sec + 3, DateTimeKind.Utc),
            TargetObject = @"HKLM\SOFTWARE\Microsoft\Windows Defender\Exclusions\Paths\C:\x" });
    }

    [Test] static void SystemBinaryAllowIsOneTimeOnly()
    {
        Assert(GuardEngine.IsSystemBinary(@"c:\windows\SYSTEM32\wscript.exe") && GuardEngine.IsSystemBinary(@"C:\Windows\SysWOW64\mshta.exe"), "sistem yolu");
        Assert(!GuardEngine.IsSystemBinary(@"C:\Windows\System32x\a.exe") && !GuardEngine.IsSystemBinary(@"C:\Windows\a.exe"), "benzer yol degil");
        string dir = NewDataDir();
        var c = new FakeControl(); var s = new FakeSink();
        var g = new GuardEngine(Rules(), dir, c, s);
        SystemToolTree(g, 6000, 0);
        Assert(c.Frozen.Count == 1 && s.Sent.Count == 1, "wscript agaci dondurulmali");
        Assert(g.OnAnswer(s.Sent[0].Id, "allow"));
        Assert(c.Resumed.Count == 1, "devam etmeli");
        Assert(!ReadData(dir, "allowed.txt").Contains(new string('B', 64)), "sistem araci izin listesine eklenmemeli");
        SystemToolTree(g, 6100, 10);
        Assert(c.Frozen.Count == 2 && s.Sent.Count == 2, "ayni imajla yeni agac yine dondurulmali");
    }

    [Test] static void DataDirAclIsProtectedWithWellKnownSids()
    {
        string dir = NewDataDir();
        Assert(GuardService.ApplyDataDirAcl(dir) == null, "ACL ayarlanmali");
        var acl = Directory.GetAccessControl(dir);
        Assert(acl.AreAccessRulesProtected, "miras kapali olmali");
        var rules = acl.GetAccessRules(true, true, typeof(System.Security.Principal.SecurityIdentifier))
            .Cast<System.Security.AccessControl.FileSystemAccessRule>().ToList();
        Func<System.Security.Principal.WellKnownSidType, System.Security.AccessControl.FileSystemRights, bool> has = (sid, r) =>
            rules.Any(x => x.IdentityReference.Equals(new System.Security.Principal.SecurityIdentifier(sid, null))
                && (x.FileSystemRights & r) == r && !x.IsInherited
                && x.InheritanceFlags == (System.Security.AccessControl.InheritanceFlags.ContainerInherit | System.Security.AccessControl.InheritanceFlags.ObjectInherit));
        Assert(rules.Count == 3, "uc kural: " + rules.Count);
        Assert(has(System.Security.Principal.WellKnownSidType.LocalSystemSid, System.Security.AccessControl.FileSystemRights.FullControl), "SYSTEM");
        Assert(has(System.Security.Principal.WellKnownSidType.BuiltinAdministratorsSid, System.Security.AccessControl.FileSystemRights.FullControl), "Administrators");
        Assert(has(System.Security.Principal.WellKnownSidType.BuiltinUsersSid, System.Security.AccessControl.FileSystemRights.ReadAndExecute), "Users");
        var users = rules.First(x => x.IdentityReference.Equals(new System.Security.Principal.SecurityIdentifier(System.Security.Principal.WellKnownSidType.BuiltinUsersSid, null)));
        Assert((users.FileSystemRights & System.Security.AccessControl.FileSystemRights.WriteData) == 0, "Users yazamamali");
    }

    // ---- kural dogrulama ----

    static byte[] ToDer(byte[] p1363)
    {
        Func<byte[], byte[]> integer = v =>
        {
            int i = 0;
            while (i < v.Length - 1 && v[i] == 0) i++;
            var b = v.Skip(i).ToList();
            if ((b[0] & 0x80) != 0) b.Insert(0, 0);
            var r = new List<byte> { 0x02, (byte)b.Count };
            r.AddRange(b);
            return r.ToArray();
        };
        var rr = integer(p1363.Take(32).ToArray());
        var ss = integer(p1363.Skip(32).ToArray());
        var der = new List<byte> { 0x30, (byte)(rr.Length + ss.Length) };
        der.AddRange(rr); der.AddRange(ss);
        return der.ToArray();
    }

    class TestKey
    {
        public System.Security.Cryptography.ECDsa Key = System.Security.Cryptography.ECDsa.Create(System.Security.Cryptography.ECCurve.NamedCurves.nistP256);
        public string X { get { return Hex(Key.ExportParameters(false).Q.X); } }
        public string Y { get { return Hex(Key.ExportParameters(false).Q.Y); } }
        public byte[] Sign(byte[] data) { return ToDer(Key.SignData(data, System.Security.Cryptography.HashAlgorithmName.SHA256)); }
        static string Hex(byte[] b) { return BitConverter.ToString(b).Replace("-", "").ToLowerInvariant(); }
    }

    static byte[] Manifest(byte[] rules)
    {
        string sha;
        using (var h = System.Security.Cryptography.SHA256.Create())
            sha = BitConverter.ToString(h.ComputeHash(rules)).Replace("-", "").ToLowerInvariant();
        return Encoding.UTF8.GetBytes("{\"files\":{\"behavior_rules.json\":{\"sha256\":\"" + sha + "\",\"size\":" + rules.Length + "}},\"version\":\"t1\"}");
    }

    static byte[] RulesBytes(int freezeAt)
    {
        string json = File.ReadAllText(RepoPath("engine/rules/behavior_rules.json"), Encoding.UTF8)
            .Replace("\"freezeAt\": 80", "\"freezeAt\": " + freezeAt);
        return Encoding.UTF8.GetBytes(json);
    }

    static void WriteSignedRules(string dir, TestKey k, byte[] rules)
    {
        byte[] m = Manifest(rules);
        File.WriteAllBytes(Path.Combine(dir, "behavior-rules.json"), rules);
        File.WriteAllBytes(Path.Combine(dir, "manifest.json"), m);
        File.WriteAllBytes(Path.Combine(dir, "manifest.sig"), k.Sign(m));
        File.WriteAllBytes(Path.Combine(dir, "behavior-rules.json.good"), RulesBytes(81));
    }

    [Test] static void SignedRulesAreLoaded()
    {
        string dir = NewDataDir(); var k = new TestKey();
        WriteSignedRules(dir, k, RulesBytes(77));
        var r = RulesStore.LoadTrusted(dir, k.X, k.Y, new GuardLog(Path.Combine(dir, "guard.log")));
        Assert(r.FreezeAt == 77, "imzali kurallar yuklenmeli: " + r.FreezeAt);
    }

    [Test] static void TamperedRulesFallBackToLastGood()
    {
        string dir = NewDataDir(); var k = new TestKey();
        WriteSignedRules(dir, k, RulesBytes(77));
        File.WriteAllBytes(Path.Combine(dir, "behavior-rules.json"), RulesBytes(10)); // icerik degisti
        var log = new GuardLog(Path.Combine(dir, "guard.log"));
        var r = RulesStore.LoadTrusted(dir, k.X, k.Y, log);
        Assert(r.FreezeAt == 81, ".good yuklenmeli: " + r.FreezeAt);
        Assert(ReadData(dir, "guard.log").Contains("behavior-rules.json.good"), "kayit satiri");

        // imza tutmazsa da .good
        string dir2 = NewDataDir();
        WriteSignedRules(dir2, k, RulesBytes(77));
        var other = new TestKey();
        File.WriteAllBytes(Path.Combine(dir2, "manifest.sig"), other.Sign(File.ReadAllBytes(Path.Combine(dir2, "manifest.json"))));
        Assert(RulesStore.LoadTrusted(dir2, k.X, k.Y, log).FreezeAt == 81, "yanlis anahtar -> .good");

        // manifest yoksa da .good
        string dir3 = NewDataDir();
        WriteSignedRules(dir3, k, RulesBytes(77));
        File.Delete(Path.Combine(dir3, "manifest.json"));
        Assert(RulesStore.LoadTrusted(dir3, k.X, k.Y, log).FreezeAt == 81, "manifest yok -> .good");
    }

    [Test] static void RuleUpdateVerifiesBeforeReplacing()
    {
        string dir = NewDataDir(); var k = new TestKey();
        WriteSignedRules(dir, k, RulesBytes(77));
        var log = new GuardLog(Path.Combine(dir, "guard.log"));
        var remote = new Dictionary<string, byte[]>();
        byte[] newRules = RulesBytes(66);
        byte[] m = Manifest(newRules);
        remote["https://x/db/manifest.json"] = m;
        remote["https://x/db/manifest.sig"] = k.Sign(m);
        remote["https://x/db/behavior_rules.json"] = RulesBytes(55); // sha tutmuyor
        Func<string, byte[]> fetch = u => { byte[] b; if (!remote.TryGetValue(u, out b)) throw new IOException("404 " + u); return b; };

        Assert(RulesStore.TryUpdate("https://x/db/", dir, k.X, k.Y, fetch, log) == null, "sha tutmayan guncelleme reddedilmeli");
        Assert(RulesStore.LoadTrusted(dir, k.X, k.Y, log).FreezeAt == 77, "eski kurallar yerinde kalmali");

        remote["https://x/db/behavior_rules.json"] = newRules;
        remote["https://x/db/manifest.sig"] = new TestKey().Sign(m);
        Assert(RulesStore.TryUpdate("https://x/db", dir, k.X, k.Y, fetch, log) == null, "imzasi tutmayan guncelleme reddedilmeli");

        remote["https://x/db/manifest.sig"] = k.Sign(m);
        var r = RulesStore.TryUpdate("https://x/db", dir, k.X, k.Y, fetch, log);
        Assert(r != null && r.FreezeAt == 66, "gecerli guncelleme kabul edilmeli");
        Assert(RulesStore.LoadTrusted(dir, k.X, k.Y, log).FreezeAt == 66, "diskteki kurallar degismeli");
        Assert(RulesStore.LoadTrusted(dir, k.X, k.Y, log).FreezeAt == 66 && File.ReadAllBytes(Path.Combine(dir, "behavior-rules.json.good")).Length > 0, ".good korunmali");
    }

    [Test] static void UpdatedRulesAreHotSwapped()
    {
        string dir = NewDataDir();
        var c = new FakeControl(); var s = new FakeSink();
        var g = new GuardEngine(Rules(), dir, c, s);
        var strict = BehaviorRules.Parse(RulesJson(d => { d["freezeAt"] = 50; d["warnAt"] = 20; }));
        g.UpdateRules(strict);
        var evs = GuardReplay.LoadEvents(RepoPath("tests/guard/replay"));
        foreach (var e in evs.Take(3)) g.OnEvent(e); // 15 + 35 = 50 >= 50
        Assert(c.Frozen.Count == 1 && s.Sent.Count == 1, "yeni esik kullanilmali");
    }

    [Test] static void SignedButInvalidRulesFallBackToLastGood()
    {
        string dir = NewDataDir(); var k = new TestKey();
        WriteSignedRules(dir, k, Encoding.UTF8.GetBytes(RulesJson(d => d["freezeAt"] = 30)));
        var r = RulesStore.LoadTrusted(dir, k.X, k.Y, new GuardLog(Path.Combine(dir, "guard.log")));
        Assert(r.FreezeAt == 81, "imzali ama gecersiz kural -> .good: " + r.FreezeAt);
        string dir2 = NewDataDir();
        WriteSignedRules(dir2, k, Encoding.UTF8.GetBytes(RulesJson(d => d.Remove("neverFreeze"))));
        Assert(RulesStore.LoadTrusted(dir2, k.X, k.Y, new GuardLog(Path.Combine(dir2, "guard.log"))).FreezeAt == 81, "eksik anahtar -> .good");

        // guncelleme de reddedilir, diskteki kurallar degismez
        string dir3 = NewDataDir();
        WriteSignedRules(dir3, k, RulesBytes(77));
        byte[] bad = Encoding.UTF8.GetBytes(RulesJson(d => d["windowSeconds"] = 5));
        byte[] m = Manifest(bad);
        var remote = new Dictionary<string, byte[]> { { "https://x/manifest.json", m }, { "https://x/manifest.sig", k.Sign(m) }, { "https://x/behavior_rules.json", bad } };
        var log = new GuardLog(Path.Combine(dir3, "guard.log"));
        Assert(RulesStore.TryUpdate("https://x", dir3, k.X, k.Y, u => remote[u], log) == null, "gecersiz guncelleme reddedilmeli");
        Assert(RulesStore.LoadTrusted(dir3, k.X, k.Y, log).FreezeAt == 77, "eski kurallar yerinde");
    }

    // ---- calistirici ----

    public static int Main(string[] args)
    {
        _repoRoot = args.Length > 0 ? args[0] : Directory.GetCurrentDirectory();
        try { Console.OutputEncoding = new UTF8Encoding(false); } catch { }
        int passed = 0, failed = 0;
        var methods = typeof(GuardTests).GetMethods(BindingFlags.Static | BindingFlags.Public | BindingFlags.NonPublic)
            .Where(m => m.GetCustomAttributes(typeof(TestAttribute), false).Length > 0)
            .OrderBy(m => m.Name, StringComparer.Ordinal);
        foreach (var m in methods)
        {
            try
            {
                m.Invoke(null, null);
                passed++;
                Console.WriteLine("PASS " + m.Name);
            }
            catch (Exception ex)
            {
                failed++;
                Exception e = ex is TargetInvocationException && ex.InnerException != null ? ex.InnerException : ex;
                Console.WriteLine("FAIL " + m.Name + ": " + e.Message.Replace("\r", " ").Replace("\n", " "));
            }
        }
        Console.WriteLine(passed + " geçti, " + failed + " kaldı");
        return failed;
    }
}
