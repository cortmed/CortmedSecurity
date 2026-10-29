using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Reflection;
using System.Text;
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
        Assert(r.NeverFreeze.Contains("lsass.exe") && r.NeverFreeze.Contains("explorer.exe"));
        Assert(r.Reasons[Behavior.Persistence] == "Kendini açılışa eklemeye çalıştı.");
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
        e.Image = @"C:\ProgramData\Microsoft\Windows Defender\Platform\4.18\MsMpEng.exe";
        e.TargetImage = @"C:\Windows\System32\lsass.exe"; e.TargetPid = 700;
        Assert(new Classifier(Rules()).Classify(e).Count == 0);
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
