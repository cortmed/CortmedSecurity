using System;
using System.Collections.Generic;
using System.Diagnostics.Eventing.Reader;
using System.Globalization;
using System.Text;
using System.Xml.Linq;

namespace Cortmed.Guard
{
    // Windows Defender'in bir tespit olayi (1116: zararli bulundu, 1117: islem yapildi).
    public class DefenderDetection
    {
        public int EventId;
        public string ThreatName = "";
        public string Severity = "";
        public string Action = "";   // ham "Action Name" (1116'da genelde "Not Applicable")
        public string User = "";
        public string RawPath = "";
        public List<string> Paths = new List<string>();
        public DateTime Time = DateTime.UtcNow;

        public string FirstPath { get { return Paths.Count > 0 ? Paths[0] : ""; } }
    }

    // Defender olay XML'inin saf ayristirmasi ve bulgu/uyari metinleri (olay gunlugu gerekmez; testler dogrudan cagirir).
    public static class DefenderEvents
    {
        static readonly XNamespace Ns = "http://schemas.microsoft.com/win/2004/08/events/event";

        // 1116/1117 degilse null. Gecersiz XML'de istisna.
        public static DefenderDetection Parse(string eventXml)
        {
            var doc = XDocument.Parse(eventXml);
            var root = doc.Root;
            if (root == null) return null;
            var sys = root.Element(Ns + "System");
            int id = 0;
            if (sys != null)
                int.TryParse((string)sys.Element(Ns + "EventID"), NumberStyles.Integer, CultureInfo.InvariantCulture, out id);
            if (id != 1116 && id != 1117) return null;

            var data = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
            var ed = root.Element(Ns + "EventData");
            if (ed != null)
                foreach (var d in ed.Elements(Ns + "Data"))
                {
                    var n = (string)d.Attribute("Name");
                    if (n != null) data[n] = d.Value;
                }

            var r = new DefenderDetection();
            r.EventId = id;
            r.ThreatName = Get(data, "Threat Name").Trim();
            r.Severity = Get(data, "Severity Name").Trim();
            r.Action = Get(data, "Action Name").Trim();
            r.User = Get(data, "Detection User").Trim();
            r.RawPath = Get(data, "Path");
            r.Paths = SplitPaths(r.RawPath);
            if (sys != null)
            {
                var tc = sys.Element(Ns + "TimeCreated");
                var st = tc == null ? null : (string)tc.Attribute("SystemTime");
                DateTime t;
                if (st != null && DateTime.TryParse(st, CultureInfo.InvariantCulture,
                    DateTimeStyles.AdjustToUniversal | DateTimeStyles.AssumeUniversal, out t))
                    r.Time = DateTime.SpecifyKind(t, DateTimeKind.Utc);
            }
            return r;
        }

        // "file:_C:\a.exe; containerfile:_C:\b.zip; webfile:_C:\c.exe|http://...|pid:1" -> dosya yollari.
        // Dosya disi ogeler (process:_, regkey:_ ...) atlanir; arsiv ici "->x" ve "\\?\" onekleri kirpilir.
        public static List<string> SplitPaths(string raw)
        {
            var list = new List<string>();
            var seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            if (string.IsNullOrEmpty(raw)) return list;
            foreach (string part in raw.Split(';'))
            {
                string s = part.Trim();
                if (s.Length == 0) continue;
                int sep = s.IndexOf(":_", StringComparison.Ordinal);
                if (sep > 0 && sep < 24 && IsWord(s.Substring(0, sep)))
                {
                    string kind = s.Substring(0, sep).ToLowerInvariant();
                    if (kind != "file" && kind != "containerfile" && kind != "webfile") continue;
                    s = s.Substring(sep + 2);
                    if (kind == "webfile")
                    {
                        int bar = s.IndexOf('|');
                        if (bar >= 0) s = s.Substring(0, bar);
                    }
                }
                int arrow = s.IndexOf("->", StringComparison.Ordinal);
                if (arrow >= 0) s = s.Substring(0, arrow);
                if (s.StartsWith(@"\\?\", StringComparison.Ordinal)) s = s.Substring(4);
                s = s.Trim();
                if (s.Length == 0 || !seen.Add(s)) continue;
                list.Add(s);
            }
            return list;
        }

        static bool IsWord(string s)
        {
            foreach (char c in s) if (!char.IsLetter(c)) return false;
            return s.Length > 0;
        }

        // Defender "Action Name" -> Turkce fiil. Islem yoksa (bos, "Not Applicable") null.
        public static string ActionVerb(string action)
        {
            string a = (action ?? "").Trim().ToLowerInvariant();
            if (a.Length == 0 || a == "not applicable" || a == "no action") return null;
            switch (a)
            {
                case "quarantine": return "karantinaya aldı";
                case "remove": return "sildi";
                case "block": return "engelledi";
                case "allow": return "izin verildi";
                default: return "durdurdu";
            }
        }

        static string ThreatOf(DefenderDetection d)
        {
            return d.ThreatName.Length > 0 ? d.ThreatName : "bilinmeyen virüs";
        }

        public static string FileName(string path)
        {
            if (string.IsNullOrEmpty(path)) return "bilinmeyen dosya";
            int i = path.LastIndexOfAny(new[] { '\\', '/' });
            string n = i >= 0 ? path.Substring(i + 1) : path;
            return n.Length > 0 ? n : path;
        }

        static bool Allowed(DefenderDetection d)
        {
            return d.EventId == 1117 && ActionVerb(d.Action) == "izin verildi";
        }

        public static string Title(DefenderDetection d)
        {
            return (Allowed(d) ? "Virüs bulundu: " : "Virüs durduruldu: ") + FileName(d.FirstPath);
        }

        public static string Detail(DefenderDetection d)
        {
            string threat = ThreatOf(d);
            if (d.EventId != 1117) return "Cortmed ve Windows Defender bu dosyada virüs buldu: " + threat + ".";
            string verb = ActionVerb(d.Action) ?? "durdurdu";
            if (verb == "izin verildi")
                return "Bu dosyada virüs bulundu ama dosyaya izin verildi: " + threat + ". Dosyayı tanımıyorsanız Windows Güvenliği'nden kaldırın.";
            if (verb == "durdurdu")
                return "Cortmed ve Windows Defender bu dosyayı durdurdu: " + threat + ". Bir şey yapmanıza gerek yok.";
            return "Cortmed ve Windows Defender bu dosyayı durdurdu ve " + verb + ": " + threat + ". Bir şey yapmanıza gerek yok.";
        }

        // Ayni tehdit + ayni dosya ayni anahtar: 1117, 1116'nin kaydini gunceller.
        public static string Key(DefenderDetection d)
        {
            string basis = d.ThreatName + "|" + d.FirstPath.ToLowerInvariant();
            return "defender:" + Hashing.Sha256(new UTF8Encoding(false).GetBytes(basis));
        }

        public static string Report(DefenderDetection d)
        {
            var sb = new StringBuilder();
            sb.AppendLine("Kaynak: Windows Defender (olay " + d.EventId + ")");
            sb.AppendLine("Tehdit: " + ThreatOf(d));
            if (d.Severity.Length > 0) sb.AppendLine("Önem: " + d.Severity);
            if (d.Paths.Count == 0) sb.AppendLine("Dosya: bilinmiyor");
            foreach (string p in d.Paths) sb.AppendLine("Dosya: " + p);
            string verb = d.EventId == 1117 ? (ActionVerb(d.Action) ?? "durdurdu") : null;
            sb.AppendLine("Yapılan işlem: " + (verb != null ? verb + (d.Action.Length > 0 ? " (" + d.Action + ")" : "") : "henüz yok (tespit edildi)"));
            if (d.User.Length > 0) sb.AppendLine("Kullanıcı: " + d.User);
            sb.AppendLine("Zaman (UTC): " + d.Time.ToUniversalTime().ToString("yyyy-MM-dd HH:mm:ss", CultureInfo.InvariantCulture));
            sb.AppendLine(Detail(d));
            return sb.ToString();
        }

        public static Dictionary<string, object> ToFinding(DefenderDetection d)
        {
            var f = new Dictionary<string, object>();
            f["key"] = Key(d);
            f["level"] = "RED";
            f["title"] = Title(d);
            f["detail"] = Detail(d);
            f["path"] = d.FirstPath;
            f["tab"] = "threat";
            f["report"] = Report(d);
            f["time"] = d.Time.ToUniversalTime().ToString("o", CultureInfo.InvariantCulture);
            return f;
        }

        static string Get(Dictionary<string, string> d, string k)
        {
            string v;
            return d.TryGetValue(k, out v) && v != null ? v : "";
        }
    }

    // Tespitleri findings.json'a yazar ve tepsiye uyari gonderir. Ayni anahtar icin 10 dakika icinde ikinci uyari yok
    // (bulgu yine guncellenir). Thread-safe; hicbir zaman istisna firlatmaz.
    public class DefenderAlerts
    {
        public static readonly TimeSpan Quiet = TimeSpan.FromMinutes(10);

        class Seen
        {
            public DateTime Alerted;
            public DateTime Last;
            public int EventId;
        }

        readonly string _findingsFile;
        readonly Func<string, string, string, string, bool> _send; // (level, title, detail, path) -> tepsiye ulasti mi
        readonly GuardLog _log;
        readonly object _lock = new object();
        readonly Dictionary<string, Seen> _seen = new Dictionary<string, Seen>();

        public DefenderAlerts(string findingsFile, Func<string, string, string, string, bool> send, GuardLog log)
        {
            _findingsFile = findingsFile;
            _send = send;
            _log = log;
        }

        // true: tepsiye uyari gonderilmeye calisildi (10 dakikalik sessizlik disinda).
        public bool Handle(DefenderDetection d, DateTime nowUtc)
        {
            if (d == null) return false;
            try
            {
                var f = DefenderEvents.ToFinding(d);
                string key = (string)f["key"];
                bool alert, write = true;
                lock (_lock)
                {
                    if (_seen.Count > 512)
                    {
                        var old = new List<string>();
                        foreach (var kv in _seen) if (nowUtc - kv.Value.Last >= Quiet) old.Add(kv.Key);
                        foreach (string k in old) _seen.Remove(k);
                    }
                    Seen s;
                    if (!_seen.TryGetValue(key, out s)) { s = new Seen { Alerted = DateTime.MinValue }; _seen[key] = s; }
                    // Islem bilgisi (1117) yakin zamanda gelen bir 1116 tekrariyla geri alinmaz
                    if (d.EventId == 1116 && s.EventId == 1117 && nowUtc - s.Last < Quiet) write = false;
                    else s.EventId = d.EventId;
                    s.Last = nowUtc;
                    alert = nowUtc - s.Alerted >= Quiet;
                    if (alert) s.Alerted = nowUtc;
                }
                if (write)
                {
                    try { FindingStore.Upsert(_findingsFile, f); }
                    catch (Exception ex) { Log("findings.json yazılamadı (Defender): " + ex.Message); }
                }
                Log("Windows Defender tespiti (olay " + d.EventId + "): " + d.ThreatName + " " + d.FirstPath
                    + (d.Action.Length > 0 ? " işlem: " + d.Action : "") + (alert ? "" : " (uyarı tekrarlanmadı)"));
                if (!alert) return false;
                bool delivered = false;
                try { delivered = _send != null && _send("RED", (string)f["title"], (string)f["detail"], (string)f["path"]); }
                catch { delivered = false; }
                if (!delivered) Log("Defender uyarısı tepsiye ulaşmadı; bulgu findings.json'da.");
                return true;
            }
            catch (Exception ex)
            {
                Log("Defender tespiti işlenemedi: " + ex.Message);
                return false;
            }
        }

        void Log(string m)
        {
            if (_log != null) _log.Write(m);
        }
    }

    // Defender Operational gunlugunu izler (1116, 1117). Hatalar yalnizca bildirilir; hizmet dusmez.
    public class DefenderWatcher : IDisposable
    {
        public const string LogName = "Microsoft-Windows-Windows Defender/Operational";
        public const string Query = "*[System[(EventID=1116 or EventID=1117)]]";

        readonly Action<DefenderDetection> _onDetection;
        readonly Action<string> _onError;
        EventLogWatcher _watcher;
        bool _failedOnce;

        public DefenderWatcher(Action<DefenderDetection> onDetection, Action<string> onError)
        {
            _onDetection = onDetection;
            _onError = onError ?? (s => { });
        }

        public bool IsWatching { get { return _watcher != null; } }

        void ReportError(string msg)
        {
            try { _onError(msg); } catch { }
        }

        // Ilk basarisizlik bir kez bildirilir (her 30 sn'de yeniden denenir; gunluk dolmasin).
        public bool Start()
        {
            if (_watcher != null) return true;
            EventLogWatcher w = null;
            try
            {
                var q = new EventLogQuery(LogName, PathType.LogName, Query);
                w = new EventLogWatcher(q);
                w.EventRecordWritten += OnRecord;
                w.Enabled = true;
                _watcher = w;
                _failedOnce = false;
                return true;
            }
            catch (Exception ex)
            {
                if (w != null) { try { w.Dispose(); } catch { } }
                _watcher = null;
                if (!_failedOnce) ReportError("Windows Defender günlüğü izlenemedi: " + ex.Message);
                _failedOnce = true;
                return false;
            }
        }

        internal void HandleXml(string xml)
        {
            DefenderDetection d;
            try { d = DefenderEvents.Parse(xml); }
            catch (Exception ex)
            {
                ReportError("Defender olayı okunamadı: " + ex.Message);
                return;
            }
            if (d == null) return;
            try { _onDetection(d); }
            catch (Exception ex) { ReportError("Defender olayı işlenemedi: " + ex.Message); }
        }

        void OnRecord(object sender, EventRecordWrittenEventArgs e)
        {
            try
            {
                if (e.EventException != null)
                {
                    ReportError("Defender olayı okunamadı: " + e.EventException.Message);
                    return;
                }
                if (e.EventRecord == null) return;
                string xml;
                using (e.EventRecord) { xml = e.EventRecord.ToXml(); }
                HandleXml(xml);
            }
            catch (Exception ex)
            {
                ReportError("Defender olayı okunamadı: " + ex.Message);
            }
        }

        public void Dispose()
        {
            var w = _watcher;
            _watcher = null;
            if (w == null) return;
            try { w.Enabled = false; } catch { }
            try { w.EventRecordWritten -= OnRecord; w.Dispose(); } catch { }
        }
    }
}
