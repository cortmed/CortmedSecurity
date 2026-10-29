using System;
using System.IO;
using System.Threading;
using Microsoft.Win32;

// Cortmed davranis bekcisi icin ZARARSIZ deneme programi (C# 5).
// Yalnizca kendi iki izini birakir: HKCU Run altinda "CortmedTest" degeri ve
// %TEMP%\CortmedFakeDiscord altinda sahte bir index.js. Gercek Discord'a dokunmaz.
static class CortmedBehaviorTest
{
    const string RunKey = @"Software\Microsoft\Windows\CurrentVersion\Run";
    const string ValueName = "CortmedTest";

    static string FakeRoot
    {
        get { return Path.Combine(Path.GetTempPath(), "CortmedFakeDiscord"); }
    }

    static string FakeIndex
    {
        get
        {
            return Path.Combine(FakeRoot,
                @"app-0.0.1\modules\discord_desktop_core-1\discord_desktop_core\index.js");
        }
    }

    static int Main(string[] args)
    {
        try { Console.OutputEncoding = new System.Text.UTF8Encoding(false); } catch { }
        foreach (string a in args)
        {
            if (string.Equals(a, "--noop", StringComparison.OrdinalIgnoreCase)) return 0;
            if (string.Equals(a, "--cleanup", StringComparison.OrdinalIgnoreCase))
            {
                Cleanup();
                Console.WriteLine("Temizlendi: CortmedTest değeri ve CortmedFakeDiscord klasörü kaldırıldı.");
                return 0;
            }
        }

        Console.WriteLine("Bu Cortmed'in zararsız deneme programıdır.");
        Console.WriteLine("Kötü niyetli bir yazılımın iki davranışını taklit eder, gerçekte hiçbir zarar vermez:");
        Console.WriteLine("  1) Açılışa eklenme: HKCU Run altına zararsız bir 'CortmedTest' değeri yazar.");
        Console.WriteLine("  2) Sahte bir Discord klasörüne (Temp altında) küçük bir index.js yazar.");
        Console.WriteLine("Gerçek Discord'a ya da başka bir programa dokunmaz.");
        Console.WriteLine("Cortmed bekçisi çalışıyorsa birkaç saniye içinde size soru sormalı.");
        Console.WriteLine("60 saniye sonra iki iz de silinir. Kapatılırsanız: CortmedBehaviorTest.exe --cleanup");
        Console.WriteLine();

        try
        {
            using (RegistryKey k = Registry.CurrentUser.CreateSubKey(RunKey))
            {
                string self = System.Reflection.Assembly.GetExecutingAssembly().Location;
                k.SetValue(ValueName, "\"" + self + "\" --noop", RegistryValueKind.String);
            }
            Console.WriteLine("Açılış değeri yazıldı.");

            Thread.Sleep(1000);

            Directory.CreateDirectory(Path.GetDirectoryName(FakeIndex));
            File.WriteAllText(FakeIndex, "// Cortmed deneme dosyasi - zararsiz\r\n");
            Console.WriteLine("Sahte Discord dosyası yazıldı.");

            Console.WriteLine("60 saniye bekleniyor...");
            Thread.Sleep(60000);
        }
        catch (Exception ex)
        {
            Console.WriteLine("Hata: " + ex.Message);
        }
        finally
        {
            Cleanup();
        }
        Console.WriteLine("Bitti, izler silindi.");
        return 0;
    }

    // Yalnizca kendi degerini ve kendi klasorunu siler.
    static void Cleanup()
    {
        try
        {
            using (RegistryKey k = Registry.CurrentUser.OpenSubKey(RunKey, true))
            {
                if (k != null) k.DeleteValue(ValueName, false);
            }
        }
        catch { }
        try
        {
            if (Directory.Exists(FakeRoot)) Directory.Delete(FakeRoot, true);
        }
        catch { }
    }
}
