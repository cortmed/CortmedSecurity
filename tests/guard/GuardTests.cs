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
