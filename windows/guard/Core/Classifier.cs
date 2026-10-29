using System;
using System.Collections.Generic;
using System.IO;

namespace Cortmed.Guard
{
    // Tek bir olayi davranis isabetlerine cevirir. Durumsuzdur.
    public class Classifier
    {
        static readonly StringComparison OIC = StringComparison.OrdinalIgnoreCase;

        static readonly string[] ScriptHosts = { "powershell.exe", "pwsh.exe", "cmd.exe", "mshta.exe", "wscript.exe", "cscript.exe" };
        static readonly string[] Browsers = { "chrome.exe", "msedge.exe", "brave.exe" };
        static readonly string[] DocFolders = { "\\Documents\\", "\\Desktop\\", "\\Pictures\\", "\\Videos\\", "\\Music\\" };

        readonly BehaviorRules _rules;

        public Classifier(BehaviorRules rules)
        {
            _rules = rules;
        }

        public List<Hit> Classify(GuardEvent e)
        {
            var hits = new List<Hit>();
            if (e == null) return hits;

            // Persistence
            if (e.EventId == 13 && (Has(e.TargetObject, "\\CurrentVersion\\Run\\") || Has(e.TargetObject, "\\RunOnce\\")))
                Add(hits, Behavior.Persistence, e.Pid);
            else if (e.EventId == 11 && Has(e.TargetFilename, "\\Start Menu\\Programs\\Startup\\"))
                Add(hits, Behavior.Persistence, e.Pid);
            else if (e.EventId == 1 && FileName(e.Image).Equals("schtasks.exe", OIC) && (Has(e.CommandLine, "/create") || Has(e.CommandLine, "-create")))
                Add(hits, Behavior.Persistence, e.ParentPid);

            // TamperOtherApp
            if (e.EventId == 11 && IsTamper(e))
                Add(hits, Behavior.TamperOtherApp, e.Pid);

            // HiddenScript
            if (e.EventId == 1 && IsOneOf(FileName(e.Image), ScriptHosts) && IsHiddenCommand(e.CommandLine))
                Add(hits, Behavior.HiddenScript, e.ParentPid);

            // DisableProtection
            if (e.EventId == 13 && (Has(e.TargetObject, "\\Windows Defender\\Exclusions\\") || Has(e.TargetObject, "DisableRealtimeMonitoring")))
                Add(hits, Behavior.DisableProtection, e.Pid);
            else if (e.EventId == 1 && (Has(e.CommandLine, "Add-MpPreference") ||
                     (Has(e.CommandLine, "Set-MpPreference") && Has(e.CommandLine, "-Disable"))))
                Add(hits, Behavior.DisableProtection, e.ParentPid);

            // Injection
            if (e.EventId == 8 && e.Pid != e.TargetPid)
                Add(hits, Behavior.Injection, e.Pid);

            // LsassAccess
            if (e.EventId == 10 && e.TargetImage != null && e.TargetImage.EndsWith("\\lsass.exe", OIC)
                && !_rules.TrustedImages.Contains(FileName(e.Image)))
                Add(hits, Behavior.LsassAccess, e.Pid);

            return hits;
        }

        // MassFileChange sayimi icin: olay 11 ve hedef kullanicinin belge klasorlerinden birinde mi.
        public static bool IsDocumentWrite(GuardEvent e)
        {
            if (e == null || e.EventId != 11) return false;
            return HasAny(e.TargetFilename, DocFolders);
        }

        void Add(List<Hit> hits, Behavior b, int pid)
        {
            string reason;
            if (!_rules.Reasons.TryGetValue(b, out reason)) reason = b.ToString();
            hits.Add(new Hit { Behavior = b, Pid = pid, Reason = reason });
        }

        // -e/-enc/.../-encodedcommand, -w|-windowstyle hidden (tam sozcuk), frombase64string (alt dize).
        static bool IsHiddenCommand(string cmd)
        {
            if (string.IsNullOrEmpty(cmd)) return false;
            if (cmd.IndexOf("frombase64string", OIC) >= 0) return true;
            var tokens = Tokenize(cmd);
            for (int i = 0; i < tokens.Count; i++)
            {
                string t = tokens[i];
                if (t.Length < 2 || (t[0] != '-' && t[0] != '/')) continue;
                string opt = t.Substring(1).ToLowerInvariant();
                if (opt == "ec" || (opt[0] == 'e' && "encodedcommand".StartsWith(opt, StringComparison.Ordinal)))
                    return true;
                if ((opt == "w" || opt == "windowstyle") && i + 1 < tokens.Count
                    && tokens[i + 1].Equals("hidden", OIC))
                    return true;
            }
            return false;
        }

        // Bosluklarla boler, cift tirnak icini tek sozcuk sayar (tirnaklar atilir).
        static List<string> Tokenize(string s)
        {
            var list = new List<string>();
            var sb = new System.Text.StringBuilder();
            bool inQ = false;
            foreach (char c in s)
            {
                if (c == '"') { inQ = !inQ; continue; }
                if (!inQ && char.IsWhiteSpace(c))
                {
                    if (sb.Length > 0) { list.Add(sb.ToString()); sb.Length = 0; }
                    continue;
                }
                sb.Append(c);
            }
            if (sb.Length > 0) list.Add(sb.ToString());
            return list;
        }

        static bool IsTamper(GuardEvent e)
        {
            string t = e.TargetFilename;
            if (t == null) return false;
            bool core = Has(t, "\\discord_desktop_core\\");
            bool ext = IsExtensionPath(t);
            if (!core && !ext) return false;

            string writer = FileName(e.Image);
            if (ext && IsOneOf(writer, Browsers)) return false;

            string a = LocalAppFolder(e.Image);
            string b = LocalAppFolder(t);
            if (a != null && b != null && a.Equals(b, OIC)) return false;
            return true;
        }

        // ...\User Data\<profil>\Extensions\...
        static bool IsExtensionPath(string path)
        {
            int u = path.IndexOf("\\User Data\\", OIC);
            if (u < 0) return false;
            return path.IndexOf("\\Extensions\\", u, OIC) >= 0;
        }

        // %LOCALAPPDATA%\<Uygulama> -> "<Uygulama>"; yoksa null.
        static string LocalAppFolder(string path)
        {
            if (string.IsNullOrEmpty(path)) return null;
            const string marker = "\\AppData\\Local\\";
            int i = path.IndexOf(marker, OIC);
            if (i < 0) return null;
            int start = i + marker.Length;
            int end = path.IndexOf('\\', start);
            if (end < 0) return null;
            return path.Substring(start, end - start);
        }

        static string FileName(string path)
        {
            if (string.IsNullOrEmpty(path)) return "";
            int i = path.LastIndexOfAny(new[] { '\\', '/' });
            return i >= 0 ? path.Substring(i + 1) : path;
        }

        static bool Has(string s, string part)
        {
            return s != null && s.IndexOf(part, OIC) >= 0;
        }

        static bool HasAny(string s, string[] parts)
        {
            if (s == null) return false;
            foreach (var p in parts) if (s.IndexOf(p, OIC) >= 0) return true;
            return false;
        }

        static bool IsOneOf(string name, string[] set)
        {
            foreach (var p in set) if (name.Equals(p, OIC)) return true;
            return false;
        }
    }
}
