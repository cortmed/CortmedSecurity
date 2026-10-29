using System;
using System.Collections.Generic;
using System.IO;

namespace Cortmed.Guard
{
    // Kural yollarindaki belirteclerin ({System32} gibi) karsiligi olan klasorler.
    // Ortam degiskeni okunmaz; dosya/kayit defteri G/C yapilmaz.
    public class KnownFolders
    {
        public string System32;
        public string SysWOW64;
        public string Windows;
        public string ProgramFiles;
        public string ProgramFilesX86;
        public string ProgramData;
        public string Users;

        static KnownFolders _current;

        public static KnownFolders Current
        {
            get
            {
                var k = _current;
                if (k == null) { k = FromEnvironment(); _current = k; }
                return k;
            }
        }

        // Hizmet 64 bit calisir (anycpu); ProgramFiles 64 bit klasordur.
        // Users: sistem surucusunun \Users klasoru (varsayilan profil yeri).
        public static KnownFolders FromEnvironment()
        {
            var k = new KnownFolders();
            k.System32 = Environment.SystemDirectory;
            k.Windows = Path.GetDirectoryName(k.System32);
            k.SysWOW64 = Path.Combine(k.Windows, "SysWOW64");
            k.ProgramFiles = Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles);
            k.ProgramFilesX86 = Environment.GetFolderPath(Environment.SpecialFolder.ProgramFilesX86);
            k.ProgramData = Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData);
            k.Users = Path.Combine(Path.GetPathRoot(k.System32), "Users");
            return k;
        }

        public string Resolve(string token)
        {
            switch (token)
            {
                case "System32": return System32;
                case "SysWOW64": return SysWOW64;
                case "Windows": return Windows;
                case "ProgramFiles": return ProgramFiles;
                case "ProgramFilesX86": return ProgramFilesX86;
                case "ProgramData": return ProgramData;
                case "Users": return Users;
                default: return null;
            }
        }
    }

    // Tam yol kaliplari: "{Belirtec}\a\b.exe" ya da "C:\a\b.exe"; "*" tek bir klasor adina uyar.
    // Karsilastirma buyuk/kucuk harf duyarsiz, klasor klasor yapilir (yalniz dosya adi asla yetmez).
    public static class PathRules
    {
        static readonly StringComparison OIC = StringComparison.OrdinalIgnoreCase;
        static readonly string[] Tokens = { "System32", "SysWOW64", "Windows", "ProgramFiles", "ProgramFilesX86", "ProgramData", "Users" };

        // %SystemRoot%\System32 ya da SysWOW64 altindaki Windows hizmet/araci surecleri:
        // cocuklari kendi agaclarini baslatir ve kendileri asla dondurulmaz.
        static readonly string[] WindowsHosts =
        {
            "svchost.exe", "WmiPrvSE.exe", "taskhostw.exe", "dllhost.exe", "RuntimeBroker.exe", "sihost.exe", "userinit.exe", "winlogon.exe"
        };

        public static bool IsValidPattern(string p)
        {
            if (string.IsNullOrEmpty(p) || p.Trim() != p) return false;
            if (p.Length >= 3 && char.IsLetter(p[0]) && p[1] == ':' && p[2] == '\\') return p.Length > 3;
            if (p[0] != '{') return false;
            int close = p.IndexOf('}');
            if (close < 0 || close + 2 > p.Length || p[close + 1] != '\\' || close + 2 == p.Length) return false;
            string tok = p.Substring(1, close - 1);
            return Array.IndexOf(Tokens, tok) >= 0;
        }

        static string Normalize(string path)
        {
            if (path == null) return "";
            string p = path.Trim();
            if (p.StartsWith(@"\\?\", StringComparison.Ordinal) || p.StartsWith(@"\??\", StringComparison.Ordinal)) p = p.Substring(4);
            return p.Replace('/', '\\').TrimEnd('\\');
        }

        static string Expand(string pattern, KnownFolders kf)
        {
            if (pattern.Length > 0 && pattern[0] == '{')
            {
                int close = pattern.IndexOf('}');
                if (close < 0) return null;
                string root = kf.Resolve(pattern.Substring(1, close - 1));
                if (string.IsNullOrEmpty(root)) return null;
                return root.TrimEnd('\\') + pattern.Substring(close + 1);
            }
            return pattern;
        }

        public static bool Matches(string pattern, string path, KnownFolders kf)
        {
            if (string.IsNullOrEmpty(pattern) || string.IsNullOrEmpty(path)) return false;
            string full = Expand(pattern, kf ?? KnownFolders.Current);
            if (full == null) return false;
            string[] a = Normalize(full).Split('\\');
            string[] b = Normalize(path).Split('\\');
            if (a.Length != b.Length) return false;
            for (int i = 0; i < a.Length; i++)
            {
                if (a[i] == "*" && b[i].Length > 0) continue;
                if (!a[i].Equals(b[i], OIC)) return false;
            }
            return true;
        }

        public static bool MatchesAny(IEnumerable<string> patterns, string path, KnownFolders kf)
        {
            if (patterns == null || string.IsNullOrEmpty(path)) return false;
            foreach (string p in patterns) if (Matches(p, path, kf)) return true;
            return false;
        }

        public static string FileName(string path)
        {
            if (string.IsNullOrEmpty(path)) return "";
            int i = path.LastIndexOfAny(new[] { '\\', '/' });
            return i >= 0 ? path.Substring(i + 1) : path;
        }

        // Imzali kurallardaki "launchers": klasorsuz ad dosya adiyla, "\" ile baslayan yol sonuyla eslesir.
        public static bool IsLauncher(string path, IEnumerable<string> launchers)
        {
            if (string.IsNullOrEmpty(path) || launchers == null) return false;
            string p = Normalize(path);
            string name = FileName(p);
            foreach (string l in launchers)
            {
                if (string.IsNullOrEmpty(l)) continue;
                if (l[0] == '\\') { if (p.EndsWith(l, OIC)) return true; }
                else if (name.Equals(l, OIC)) return true;
            }
            return false;
        }

        // Ebeveyni bu imaj olan surec yeni bir agac baslatir (kendi kokudur):
        // explorer.exe / services.exe (ad), System32/SysWOW64 altindaki Windows hizmet surecleri (tam yol)
        // ve imzali kurallardaki baslaticilar (tarayicilar, Discord, arsivciler...).
        public static bool IsRootStarter(string parentImage, BehaviorRules r, KnownFolders kf)
        {
            if (string.IsNullOrEmpty(parentImage)) return false;
            string name = FileName(Normalize(parentImage));
            if (name.Equals("explorer.exe", OIC) || name.Equals("services.exe", OIC)) return true;
            if (IsWindowsHost(parentImage, kf)) return true;
            return r != null && IsLauncher(parentImage, r.Launchers);
        }

        // Windows hizmet sureci: YALNIZCA tam yol {System32}\<ad>, {SysWOW64}\<ad> ya da {System32|SysWOW64}\wbem\WmiPrvSE.exe.
        // Daha derin alt klasorler asla (spool\drivers\color, Tasks, com\dmp gibi kullanicilarin yazabildigi yerler var).
        public static bool IsWindowsHost(string path, KnownFolders kf)
        {
            if (string.IsNullOrEmpty(path)) return false;
            kf = kf ?? KnownFolders.Current;
            foreach (string h in WindowsHosts)
            {
                if (Matches(@"{System32}\" + h, path, kf) || Matches(@"{SysWOW64}\" + h, path, kf)) return true;
            }
            return Matches(@"{System32}\wbem\WmiPrvSE.exe", path, kf) || Matches(@"{SysWOW64}\wbem\WmiPrvSE.exe", path, kf);
        }
    }
}
