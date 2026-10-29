using System;
using System.Collections.Generic;
using System.Diagnostics.Eventing.Reader;
using System.Globalization;
using System.Linq;
using System.ServiceProcess;
using System.Xml.Linq;

namespace Cortmed.Guard
{
    // Sysmon olaylarini okuyup GuardEvent'e cevirir.
    public class SysmonReader : IDisposable
    {
        const string LogName = "Microsoft-Windows-Sysmon/Operational";
        const string Query = "*[System[(EventID=1 or EventID=5 or EventID=8 or EventID=10 or EventID=11 or EventID=13)]]";
        static readonly XNamespace Ns = "http://schemas.microsoft.com/win/2004/08/events/event";

        readonly Action<GuardEvent> _onEvent;
        readonly Action<string> _onError;
        EventLogWatcher _watcher;

        public SysmonReader(Action<GuardEvent> onEvent) : this(onEvent, null) { }

        // Geri cagrilar (onEvent/onError) threadpool thread'inde calisir; tuketici thread-safe olmali.
        public SysmonReader(Action<GuardEvent> onEvent, Action<string> onError)
        {
            _onEvent = onEvent;
            _onError = onError ?? (s => { });
        }

        public bool IsWatching { get { return _watcher != null; } }

        void ReportError(string msg)
        {
            try { _onError(msg); } catch { }
        }

        internal void HandleXml(string xml)
        {
            GuardEvent ev;
            try { ev = FromXml(xml); }
            catch (Exception ex)
            {
                ReportError("Sysmon olay okunamadı: " + ex.Message);
                return;
            }
            try { _onEvent(ev); }
            catch (Exception ex)
            {
                ReportError("Sysmon olay işlenemedi: " + ex.Message);
            }
        }

        public static GuardEvent FromXml(string eventXml)
        {
            var doc = XDocument.Parse(eventXml);
            var root = doc.Root;
            var sys = root.Element(Ns + "System");
            var data = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
            var ed = root.Element(Ns + "EventData");
            if (ed != null)
            {
                foreach (var d in ed.Elements(Ns + "Data"))
                {
                    var n = (string)d.Attribute("Name");
                    if (n != null) data[n] = d.Value;
                }
            }

            var ev = new GuardEvent();
            ev.EventId = ToInt(sys == null ? null : (string)sys.Element(Ns + "EventID"));
            ev.Time = DateTime.UtcNow;
            if (sys != null)
            {
                var tc = sys.Element(Ns + "TimeCreated");
                var st = tc == null ? null : (string)tc.Attribute("SystemTime");
                DateTime t;
                if (st != null && DateTime.TryParse(st, CultureInfo.InvariantCulture,
                    DateTimeStyles.AdjustToUniversal | DateTimeStyles.AssumeUniversal, out t))
                    ev.Time = DateTime.SpecifyKind(t, DateTimeKind.Utc);
            }

            if (ev.EventId == 8 || ev.EventId == 10)
            {
                ev.Pid = ToInt(Get(data, "SourceProcessId"));
                ev.Image = Get(data, "SourceImage");
                ev.TargetPid = ToInt(Get(data, "TargetProcessId"));
                ev.TargetImage = Get(data, "TargetImage");
                ev.GrantedAccess = Get(data, "GrantedAccess");
            }
            else
            {
                ev.Pid = ToInt(Get(data, "ProcessId"));
                ev.Image = Get(data, "Image");
                ev.ParentPid = ToInt(Get(data, "ParentProcessId"));
                ev.ParentImage = Get(data, "ParentImage");
            }
            ev.CommandLine = Get(data, "CommandLine");
            ev.TargetObject = Get(data, "TargetObject");
            ev.TargetFilename = Get(data, "TargetFilename");
            ev.Hashes = Get(data, "Hashes");
            return ev;
        }

        // "SHA256=ABC,IMPHASH=..." -> "ABC" (buyuk harf), yoksa "".
        public static string Sha256Of(string hashes)
        {
            if (string.IsNullOrEmpty(hashes)) return "";
            foreach (var part in hashes.Split(','))
            {
                var p = part.Trim();
                if (p.StartsWith("SHA256=", StringComparison.OrdinalIgnoreCase))
                    return p.Substring(7).Trim().ToUpperInvariant();
            }
            return "";
        }

        public bool IsSysmonRunning()
        {
            foreach (var name in new[] { "Sysmon64", "Sysmon" })
            {
                try
                {
                    using (var sc = new ServiceController(name))
                    {
                        if (sc.Status == ServiceControllerStatus.Running) return true;
                    }
                }
                catch { }
            }
            return false;
        }

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
                return true;
            }
            catch (Exception ex)
            {
                if (w != null) { try { w.Dispose(); } catch { } }
                _watcher = null;
                ReportError("Sysmon günlüğü izlenemedi: " + ex.Message);
                return false;
            }
        }

        void OnRecord(object sender, EventRecordWrittenEventArgs e)
        {
            try
            {
                if (e.EventException != null)
                {
                    ReportError("Sysmon olay okunamadı: " + e.EventException.Message);
                    return;
                }
                if (e.EventRecord == null) return;
                string xml;
                using (e.EventRecord) { xml = e.EventRecord.ToXml(); }
                HandleXml(xml);
            }
            catch (Exception ex)
            {
                ReportError("Sysmon olay okunamadı: " + ex.Message);
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

        static string Get(Dictionary<string, string> d, string key)
        {
            string v;
            return d.TryGetValue(key, out v) ? v : null;
        }

        static int ToInt(string s)
        {
            int v;
            return int.TryParse(s, NumberStyles.Integer, CultureInfo.InvariantCulture, out v) ? v : 0;
        }
    }
}
