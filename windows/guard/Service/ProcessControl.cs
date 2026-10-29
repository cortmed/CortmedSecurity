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

        static string ImageName(int pid)
        {
            // Once Process sinifi, olmazsa sinirli tutamac ile tam yol.
            try { return Process.GetProcessById(pid).ProcessName + ".exe"; } catch { }
            IntPtr h = IntPtr.Zero;
            try
            {
                h = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, pid);
                if (h == IntPtr.Zero) return null;
                var sb = new StringBuilder(1024);
                int size = sb.Capacity;
                if (!QueryFullProcessImageName(h, 0, sb, ref size)) return null;
                return Path.GetFileName(sb.ToString());
            }
            catch { return null; }
            finally { if (h != IntPtr.Zero) CloseHandle(h); }
        }

        public static bool CanFreeze(int pid, BehaviorRules r)
        {
            try
            {
                if (pid <= 4) return false; // 0 Idle, 4 System
                if (pid == Process.GetCurrentProcess().Id) return false;
                string name = ImageName(pid);
                if (name == null) return false; // adi okunamayan surec dondurulmez
                if (r != null && r.NeverFreeze.Contains(name)) return false;
                if (r != null && name.EndsWith(".exe", StringComparison.OrdinalIgnoreCase) &&
                    r.NeverFreeze.Contains(name.Substring(0, name.Length - 4))) return false;
                return true;
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
