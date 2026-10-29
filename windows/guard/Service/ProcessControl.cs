using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Runtime.InteropServices;
using System.Text;

namespace Cortmed.Guard
{
    // Surec agacini dondurma / devam ettirme / kapatma. Hicbir metot istisna firlatmaz.
    public static class ProcessControl
    {
        const uint PROCESS_SUSPEND_RESUME = 0x0800;
        const uint PROCESS_QUERY_LIMITED_INFORMATION = 0x1000;

        [DllImport("ntdll.dll")] static extern int NtSuspendProcess(IntPtr h);
        [DllImport("ntdll.dll")] static extern int NtResumeProcess(IntPtr h);
        [DllImport("kernel32.dll", SetLastError = true)]
        static extern IntPtr OpenProcess(uint access, bool inherit, int pid);
        [DllImport("kernel32.dll", SetLastError = true)]
        static extern bool CloseHandle(IntPtr h);
        [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
        static extern bool QueryFullProcessImageName(IntPtr h, int flags, StringBuilder name, ref int size);

        // Asla dondurulmayan surecler, sistemdeki TAM yollariyla. Imzali kurallar (NeverFreeze) bu
        // listeye ekleyebilir ama cikaramaz. "System" (pid 4) ve yolu okunamayan surecler zaten dondurulmaz.
        static readonly string[] NeverFreezeFloor =
        {
            @"{System32}\smss.exe", @"{System32}\csrss.exe", @"{System32}\wininit.exe", @"{System32}\winlogon.exe",
            @"{System32}\services.exe", @"{System32}\lsass.exe", @"{Windows}\explorer.exe", @"{System32}\dwm.exe",
            @"{ProgramFiles}\Cortmed\CortmedGuard.exe",
            @"{Users}\*\AppData\Local\CortmedSecurity\CortmedSecurity.exe"
        };

        // Surecin tam imaj yolu (QueryFullProcessImageName); okunamazsa null.
        public static string FullImagePath(int pid)
        {
            IntPtr h = IntPtr.Zero;
            try
            {
                h = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, pid);
                if (h == IntPtr.Zero) return null;
                var sb = new StringBuilder(1024);
                int size = sb.Capacity;
                if (!QueryFullProcessImageName(h, 0, sb, ref size)) return null;
                return sb.ToString();
            }
            catch { return null; }
            finally { if (h != IntPtr.Zero) CloseHandle(h); }
        }

        // Saf karar (canli surece bakmaz): bu tam yoldaki surec asla dondurulmez mi?
        public static bool IsProtectedImage(string fullPath, BehaviorRules r)
        {
            if (string.IsNullOrEmpty(fullPath)) return true;
            var kf = KnownFolders.Current;
            if (PathRules.MatchesAny(NeverFreezeFloor, fullPath, kf)) return true;
            if (r != null && PathRules.MatchesAny(r.NeverFreeze, fullPath, kf)) return true;
            return false;
        }

        // Saf karar: tam yol ve oturum numarasi verilen surec dondurulebilir mi?
        public static bool CanFreezeImage(string fullPath, int sessionId, BehaviorRules r)
        {
            return !IsProtectedImage(fullPath, r);
        }

        public static bool CanFreeze(int pid, BehaviorRules r)
        {
            try
            {
                if (pid <= 4) return false; // 0 Idle, 4 System
                if (pid == Process.GetCurrentProcess().Id) return false;
                string path = FullImagePath(pid);
                if (path == null) return false; // yolu okunamayan surec dondurulmez
                return CanFreezeImage(path, 1, r);
            }
            catch { return false; }
        }

        // Dondurulabilenleri dondurur ve dondurulenlerin listesini verir.
        public static List<int> FreezeTree(List<int> pids, BehaviorRules r)
        {
            var frozen = new List<int>();
            if (pids == null) return frozen;
            foreach (int pid in pids)
            {
                try
                {
                    if (!CanFreeze(pid, r)) continue;
                    IntPtr h = OpenProcess(PROCESS_SUSPEND_RESUME | PROCESS_QUERY_LIMITED_INFORMATION, false, pid);
                    if (h == IntPtr.Zero) continue;
                    try { if (NtSuspendProcess(h) >= 0) frozen.Add(pid); }
                    finally { CloseHandle(h); }
                }
                catch { }
            }
            return frozen;
        }

        public static void ResumeTree(List<int> pids)
        {
            if (pids == null) return;
            foreach (int pid in pids)
            {
                try
                {
                    IntPtr h = OpenProcess(PROCESS_SUSPEND_RESUME | PROCESS_QUERY_LIMITED_INFORMATION, false, pid);
                    if (h == IntPtr.Zero) continue;
                    try { NtResumeProcess(h); }
                    finally { CloseHandle(h); }
                }
                catch { }
            }
        }

        // Beklenen sira: kok once, torunlar sonra (ProcessTree.Subtree sirasi).
        // Yapraktan koke kapatmak icin liste tersten islenir.
        public static void KillTree(List<int> pids)
        {
            if (pids == null) return;
            for (int i = pids.Count - 1; i >= 0; i--)
            {
                try
                {
                    int pid = pids[i];
                    if (pid <= 4 || pid == Process.GetCurrentProcess().Id) continue;
                    using (var p = Process.GetProcessById(pid)) { p.Kill(); }
                }
                catch { }
            }
        }
    }
}
