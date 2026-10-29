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
