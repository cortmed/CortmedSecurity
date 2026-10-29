using System;
using System.Collections;
using System.Collections.Generic;
using System.Diagnostics;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Net;
using System.Security.AccessControl;
using System.Security.Principal;
using System.ServiceProcess;
using System.Text;
using System.Threading;
using System.Web.Script.Serialization;

namespace Cortmed.Guard
{
    // Gercek surec kontrolu: Task 5'in statik ProcessControl'u. Rules kural guncellemesinde degisir.
    public class RealProcessControl : IProcessControl
    {
        volatile BehaviorRules _rules;

        public RealProcessControl(BehaviorRules rules)
        {
            _rules = rules;
        }

        public BehaviorRules Rules
        {
            get { return _rules; }
            set { if (value != null) _rules = value; }
        }

        // ProcessControl.FreezeTree her pid icin CanFreeze kontrolu yapar (NeverFreeze, System, kendisi).
        public List<int> FreezeTree(List<int> pids) { return ProcessControl.FreezeTree(pids, _rules); }
        public void ResumeTree(List<int> pids) { ProcessControl.ResumeTree(pids); }
        public void KillTree(List<int> pids) { ProcessControl.KillTree(pids); }

        public int SessionOf(int pid) { return ProcessControl.SessionOf(pid); }

        public long StartTimeOf(int pid)
        {
            try
            {
                using (var p = System.Diagnostics.Process.GetProcessById(pid))
                    return p.StartTime.ToUniversalTime().Ticks;
            }
            catch { return 0; }
        }
    }

    // Tepsiye GuardPipe uzerinden soru gonderir.
    public class PipePromptSink : IPromptSink
    {
        readonly GuardPipe _pipe;

        public PipePromptSink(GuardPipe pipe)
        {
            _pipe = pipe;
        }

        public bool HasClient { get { return _pipe.HasClient; } }
        public bool Send(Prompt p) { return _pipe.SendPrompt(p); }
        public bool Withdraw(string id) { return _pipe.SendWithdraw(id); }
    }

    // Davranis kurallarinin imzali yuklenmesi ve gunluk guncellemesi.
    // Guvenilir kurallar: manifest.json imzasi (ECDSA P-256, gece isinin anahtari) tutar VE
    // behavior-rules.json'in SHA-256'si manifest'teki "behavior_rules.json" kaydiyla ayni.
    // Dogrulanmamis kural asla yuklenmez; olmazsa kurulumun biraktigi behavior-rules.json.good.
    public static class RulesStore
    {
        public const string PublicX = "26e0318081d8d3d4defd932169992251c7f4d08d46a95f395ccd22c1c48c72c5";
        public const string PublicY = "13cd8f7df0bdca9f67cd720e1f42e4174033842a5601d9c98bf68e2ef2402f4f";
        public const string DefaultUpdateUrl = "https://github.com/cortmed/CortmedSecurity/releases/download/db-latest";
        public const string RulesFile = "behavior-rules.json";
        public const string GoodFile = "behavior-rules.json.good";
        public const string ManifestFile = "manifest.json";
        public const string SigFile = "manifest.sig";
        public const string RemoteRulesName = "behavior_rules.json";
        const int MaxDownload = 4 * 1024 * 1024;

        // null: gecerli; aksi halde Turkce neden.
        public static string Check(byte[] manifest, byte[] sig, byte[] rules, string xHex, string yHex)
        {
            if (manifest == null) return "manifest.json yok";
            if (sig == null) return "manifest.sig yok";
            if (!Signing.Verify(manifest, sig, xHex, yHex)) return "manifest imzası tutmuyor";
            string sha;
            long size;
            string why = RulesEntry(manifest, out sha, out size);
            if (why != null) return why;
            if (rules == null) return "kural dosyası yok";
            if (!string.Equals(Hashing.Sha256(rules), sha, StringComparison.OrdinalIgnoreCase)) return "kural dosyasının SHA-256'sı manifest ile tutmuyor";
            if (size >= 0 && size != rules.LongLength) return "kural dosyasının boyutu manifest ile tutmuyor";
            return null;
        }

        static string RulesEntry(byte[] manifest, out string sha, out long size)
        {
            sha = null;
            size = -1;
            try
            {
                var root = new JavaScriptSerializer().DeserializeObject(StripBom(Encoding.UTF8.GetString(manifest))) as Dictionary<string, object>;
                if (root == null) return "manifest bir nesne değil";
                object files, entry, s, n;
                if (!root.TryGetValue("files", out files) || !(files is Dictionary<string, object>)) return "manifest'te dosya listesi yok";
                if (!((Dictionary<string, object>)files).TryGetValue(RemoteRulesName, out entry) || !(entry is Dictionary<string, object>))
                    return "manifest'te " + RemoteRulesName + " yok";
                var e = (Dictionary<string, object>)entry;
                if (!e.TryGetValue("sha256", out s) || !(s is string) || !Hashing.IsSha256Hex((string)s)) return "manifest'te geçerli sha256 yok";
                sha = (string)s;
                if (e.TryGetValue("size", out n) && n != null) size = Convert.ToInt64(n, CultureInfo.InvariantCulture);
                return null;
            }
            catch (Exception ex) { return "manifest okunamadı: " + ex.Message; }
        }

        static string StripBom(string s)
        {
            return s.Length > 0 && s[0] == '﻿' ? s.Substring(1) : s;
        }

        static BehaviorRules Parse(byte[] rules)
        {
            return BehaviorRules.Parse(StripBom(Encoding.UTF8.GetString(rules)));
        }

        static byte[] ReadOrNull(string path)
        {
            try { return File.Exists(path) ? File.ReadAllBytes(path) : null; }
            catch { return null; }
        }

        // Dogrulanmis kurallari yukler; olmazsa .good. .good da okunamazsa istisna (hizmet kuralsiz calismaz).
        public static BehaviorRules LoadTrusted(string dataDir, string xHex, string yHex, GuardLog log)
        {
            string reason;
            try
            {
                byte[] rules = ReadOrNull(Path.Combine(dataDir, RulesFile));
                reason = Check(ReadOrNull(Path.Combine(dataDir, ManifestFile)), ReadOrNull(Path.Combine(dataDir, SigFile)), rules, xHex, yHex);
                if (reason == null)
                {
                    var r = Parse(rules);
                    if (log != null) log.Write("Davranış kuralları imzası doğrulanarak yüklendi.");
                    return r;
                }
            }
            catch (Exception ex) { reason = ex.Message; }
            if (log != null) log.Write("Davranış kuralları doğrulanamadı (" + reason + "); son geçerli kopya " + GoodFile + " yükleniyor.");
            byte[] good = File.ReadAllBytes(Path.Combine(dataDir, GoodFile));
            return Parse(good);
        }

        // Uc dosyayi indirir, imza + SHA-256 + ayristirma tutarsa diske yazar ve yeni kurallari verir.
        // Degisiklik yoksa ya da herhangi bir adim tutmazsa null (diskteki dosyalar degismez).
        public static BehaviorRules TryUpdate(string baseUrl, string dataDir, string xHex, string yHex, Func<string, byte[]> fetch, GuardLog log)
        {
            try
            {
                string b = (baseUrl ?? "").Trim().TrimEnd('/');
                if (b.Length == 0) return null;
                byte[] manifest = fetch(b + "/" + ManifestFile);
                byte[] sig = fetch(b + "/" + SigFile);
                if (manifest == null || sig == null || !Signing.Verify(manifest, sig, xHex, yHex))
                {
                    log.Write("Kural güncellemesi reddedildi: manifest imzası tutmuyor.");
                    return null;
                }
                string sha;
                long size;
                string why = RulesEntry(manifest, out sha, out size);
                if (why != null)
                {
                    log.Write("Kural güncellemesi atlandı: " + why);
                    return null;
                }
                byte[] rules = fetch(b + "/" + RemoteRulesName);
                why = Check(manifest, sig, rules, xHex, yHex);
                if (why != null)
                {
                    log.Write("Kural güncellemesi reddedildi: " + why);
                    return null;
                }
                var parsed = Parse(rules); // bozuksa istisna: diske yazilmaz

                string rulesPath = Path.Combine(dataDir, RulesFile);
                byte[] cur = ReadOrNull(rulesPath);
                byte[] curManifest = ReadOrNull(Path.Combine(dataDir, ManifestFile));
                if (cur != null && curManifest != null && cur.SequenceEqual(rules) && curManifest.SequenceEqual(manifest)
                    && Check(curManifest, ReadOrNull(Path.Combine(dataDir, SigFile)), cur, xHex, yHex) == null)
                {
                    log.Write("Davranış kuralları güncel.");
                    return null;
                }
                // Yarida kalirsa bir sonraki baslangicta dogrulama tutmaz ve .good yuklenir (asla dogrulanmamis kural yok).
                AtomicFile.WriteAllBytes(rulesPath, rules);
                AtomicFile.WriteAllBytes(Path.Combine(dataDir, ManifestFile), manifest);
                AtomicFile.WriteAllBytes(Path.Combine(dataDir, SigFile), sig);
                log.Write("Davranış kuralları güncellendi (imza ve SHA-256 doğrulandı).");
                return parsed;
            }
            catch (Exception ex)
            {
                log.Write("Kural güncellemesi yapılamadı: " + ex.Message);
                return null;
            }
        }

        // HTTPS indirme: 30 sn zaman asimi, 4 MB sinir.
        public static byte[] WebFetch(string url)
        {
            ServicePointManager.SecurityProtocol |= SecurityProtocolType.Tls12;
            var req = (HttpWebRequest)WebRequest.Create(url);
            req.Timeout = 30000;
            req.ReadWriteTimeout = 30000;
            req.AllowAutoRedirect = true;
            req.UserAgent = "CortmedGuard";
            using (var resp = (HttpWebResponse)req.GetResponse())
            using (var s = resp.GetResponseStream())
            using (var ms = new MemoryStream())
            {
                byte[] buf = new byte[8192];
                int n;
                while ((n = s.Read(buf, 0, buf.Length)) > 0)
                {
                    ms.Write(buf, 0, n);
                    if (ms.Length > MaxDownload) throw new IOException("dosya çok büyük: " + url);
                }
                return ms.ToArray();
            }
        }
    }

    // --replay icin olay dosyalari: klasordeki *.json dosyalari ordinal ad sirasiyla; her dosya
    // bir GuardEvent nesnesi ya da dizisi (alan adlari GuardEvent ile ayni, Time ISO-8601 UTC).
    public static class GuardReplay
    {
        public static List<GuardEvent> LoadEvents(string folder)
        {
            var list = new List<GuardEvent>();
            var files = Directory.GetFiles(folder, "*.json").OrderBy(f => f, StringComparer.Ordinal);
            foreach (string file in files)
            {
                var ser = new JavaScriptSerializer();
                ser.MaxJsonLength = int.MaxValue;
                string text = File.ReadAllText(file, Encoding.UTF8);
                object parsed = ser.DeserializeObject(text);
                var arr = parsed as object[];
                if (arr != null)
                {
                    foreach (object o in arr)
                    {
                        var d = o as Dictionary<string, object>;
                        if (d == null) throw new InvalidDataException(Path.GetFileName(file) + ": dizi elemanı nesne değil");
                        list.Add(Parse(d));
                    }
                }
                else
                {
                    var d = parsed as Dictionary<string, object>;
                    if (d == null) throw new InvalidDataException(Path.GetFileName(file) + ": nesne ya da dizi değil");
                    list.Add(Parse(d));
                }
            }
            return list;
        }

        public static GuardEvent Parse(Dictionary<string, object> d)
        {
            var e = new GuardEvent();
            e.EventId = Int(d, "EventId");
            e.Pid = Int(d, "Pid");
            e.ParentPid = Int(d, "ParentPid");
            e.TargetPid = Int(d, "TargetPid");
            e.Image = Str(d, "Image");
            e.ParentImage = Str(d, "ParentImage");
            e.CommandLine = Str(d, "CommandLine");
            e.TargetObject = Str(d, "TargetObject");
            e.TargetFilename = Str(d, "TargetFilename");
            e.TargetImage = Str(d, "TargetImage");
            e.Hashes = Str(d, "Hashes");
            e.GrantedAccess = Str(d, "GrantedAccess");
            e.Details = Str(d, "Details");
            string t = Str(d, "Time");
            e.Time = string.IsNullOrEmpty(t)
                ? DateTime.UtcNow
                : DateTime.Parse(t, CultureInfo.InvariantCulture, DateTimeStyles.AssumeUniversal | DateTimeStyles.AdjustToUniversal);
            return e;
        }

        static string Str(Dictionary<string, object> d, string k)
        {
            object v;
            return d.TryGetValue(k, out v) && v != null ? Convert.ToString(v, CultureInfo.InvariantCulture) : null;
        }

        static int Int(Dictionary<string, object> d, string k)
        {
            object v;
            return d.TryGetValue(k, out v) && v != null ? Convert.ToInt32(v, CultureInfo.InvariantCulture) : 0;
        }
    }

    // Replay: hicbir surece dokunmaz; dondurma "basarili" sayilir, tepsi yok.
    class ReplayControl : IProcessControl
    {
        public List<int> FreezeTree(List<int> pids) { return new List<int>(pids); }
        public void ResumeTree(List<int> pids) { }
        public void KillTree(List<int> pids) { }
        public long StartTimeOf(int pid) { return 1; }
        public int SessionOf(int pid) { return 1; }
    }

    class NoSink : IPromptSink
    {
        public bool HasClient { get { return false; } }
        public bool Send(Prompt p) { return false; }
        public bool Withdraw(string id) { return false; }
    }

    // CortmedGuard Windows hizmeti (SYSTEM).
    public class GuardService : ServiceBase
    {
        public const string Name = "CortmedGuard";
        public const string PipeName = "CortmedGuard";

        public static string DefaultDataDir
        {
            get { return Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData), "Cortmed"); }
        }

        readonly string _dataDir;
        GuardLog _log;
        GuardEngine _engine;
        GuardPipe _pipe;
        SysmonReader _reader;
        RealProcessControl _control;
        Timer _sysmonTimer;
        Timer _updateTimer;
        int _sysmonBusy;
        int _updateBusy;
        bool _lastSysmonOk = true;
        volatile bool _stopping;

        public GuardService(string dataDir)
        {
            ServiceName = Name;
            CanStop = true;
            CanShutdown = true;
            AutoLog = true;
            _dataDir = dataDir;
        }

        protected override void OnStart(string[] args) { StartGuard(true); }
        protected override void OnStop() { StopGuard(); }
        protected override void OnShutdown() { StopGuard(); }

        // secureDataDir: yalnizca hizmet modunda (SYSTEM) veri klasorunun ACL'si sertlestirilir.
        public void StartGuard(bool secureDataDir)
        {
            Directory.CreateDirectory(_dataDir);
            _log = new GuardLog(Path.Combine(_dataDir, "guard.log"));
            _log.Write("CortmedGuard başlıyor.");
            if (secureDataDir)
            {
                string err = ApplyDataDirAcl(_dataDir);
                if (err != null) _log.Write("Veri klasörü izinleri ayarlanamadı: " + err);
            }
            BehaviorRules rules;
            try { rules = RulesStore.LoadTrusted(_dataDir, RulesStore.PublicX, RulesStore.PublicY, _log); }
            catch (Exception ex)
            {
                _log.Write("Geçerli davranış kuralı bulunamadı, bekçi başlatılamadı: " + ex.Message);
                throw;
            }
            _control = new RealProcessControl(rules);
            _pipe = new GuardPipe(PipeName, OnAnswer);
            _engine = new GuardEngine(rules, _dataDir, _control, new PipePromptSink(_pipe), _log);
            _pipe.Connected = OnPipeConnected;
            _pipe.Start();
            _reader = new SysmonReader(_engine.OnEvent, msg => _log.Write(msg));
            if (_reader.Start()) _log.Write("Sysmon günlüğü izleniyor.");
            _sysmonTimer = new Timer(SysmonTick, null, 0, 30000);
            _updateTimer = new Timer(UpdateTick, null, TimeSpan.FromMinutes(2), TimeSpan.FromHours(24));
        }

        // Korunan (miras almayan) ACL: SYSTEM ve Administrators tam yetki, Users okuma/calistirma;
        // alt klasor ve dosyalara miras. Yerellestirilmis adlar yerine iyi bilinen SID'ler. null: basarili.
        public static string ApplyDataDirAcl(string dir)
        {
            try
            {
                var ds = new DirectorySecurity();
                ds.SetAccessRuleProtection(true, false);
                var inherit = InheritanceFlags.ContainerInherit | InheritanceFlags.ObjectInherit;
                ds.AddAccessRule(new FileSystemAccessRule(new SecurityIdentifier(WellKnownSidType.LocalSystemSid, null),
                    FileSystemRights.FullControl, inherit, PropagationFlags.None, AccessControlType.Allow));
                ds.AddAccessRule(new FileSystemAccessRule(new SecurityIdentifier(WellKnownSidType.BuiltinAdministratorsSid, null),
                    FileSystemRights.FullControl, inherit, PropagationFlags.None, AccessControlType.Allow));
                ds.AddAccessRule(new FileSystemAccessRule(new SecurityIdentifier(WellKnownSidType.BuiltinUsersSid, null),
                    FileSystemRights.ReadAndExecute, inherit, PropagationFlags.None, AccessControlType.Allow));
                Directory.SetAccessControl(dir, ds);
                return null;
            }
            catch (Exception ex) { return ex.Message; }
        }

        public void StopGuard()
        {
            _stopping = true;
            if (_log != null) _log.Write("CortmedGuard duruyor (donuk süreçler donuk kalır, sorular pending.json'da).");
            if (_sysmonTimer != null) { _sysmonTimer.Dispose(); _sysmonTimer = null; }
            if (_updateTimer != null) { _updateTimer.Dispose(); _updateTimer = null; }
            if (_reader != null) { _reader.Dispose(); _reader = null; }
            if (_pipe != null) { _pipe.Dispose(); _pipe = null; }
        }

        bool OnAnswer(string id, string decision)
        {
            var e = _engine;
            return e != null && e.OnAnswer(id, decision);
        }

        void OnPipeConnected()
        {
            SendStatus();
            var e = _engine;
            if (e != null) e.OnClientConnected();
        }

        void SendStatus()
        {
            var p = _pipe;
            var r = _reader;
            if (p == null || r == null) return;
            p.SendStatus(r.IsSysmonRunning(), File.Exists(Path.Combine(_dataDir, "sysmon-preexisting")));
        }

        void SysmonTick(object state)
        {
            if (_stopping || Interlocked.CompareExchange(ref _sysmonBusy, 1, 0) != 0) return;
            try
            {
                var r = _reader;
                if (r == null || _stopping) return;
                bool ok = r.IsSysmonRunning();
                if (!ok)
                {
                    if (_lastSysmonOk) _log.Write("Sysmon çalışmıyor; yeniden başlatılıyor.");
                    TryStartService("Sysmon64");
                    ok = r.IsSysmonRunning();
                    if (!ok) { TryStartService("Sysmon"); ok = r.IsSysmonRunning(); }
                    if (ok) _log.Write("Sysmon yeniden başlatıldı.");
                }
                if (ok && !_stopping && !r.IsWatching && r.Start()) _log.Write("Sysmon günlüğü izleniyor.");
                if (!ok && _lastSysmonOk) _log.Write("Sysmon başlatılamadı; davranış bekçisi kapalı.");
                _lastSysmonOk = ok;
                SendStatus();
            }
            catch (Exception ex) { _log.Write("Sysmon denetimi hatası: " + ex.Message); }
            finally { Interlocked.Exchange(ref _sysmonBusy, 0); }
        }

        static void TryStartService(string name)
        {
            try
            {
                var psi = new ProcessStartInfo(Path.Combine(Environment.SystemDirectory, "sc.exe"), "start " + name);
                psi.UseShellExecute = false;
                psi.CreateNoWindow = true;
                psi.RedirectStandardOutput = true;
                using (var p = System.Diagnostics.Process.Start(psi))
                {
                    p.StandardOutput.ReadToEnd();
                    p.WaitForExit(15000);
                }
                Thread.Sleep(1000);
            }
            catch { }
        }

        void UpdateTick(object state)
        {
            if (_stopping || Interlocked.CompareExchange(ref _updateBusy, 1, 0) != 0) return;
            try
            {
                var r = RulesStore.TryUpdate(RulesStore.DefaultUpdateUrl, _dataDir, RulesStore.PublicX, RulesStore.PublicY, RulesStore.WebFetch, _log);
                if (r != null)
                {
                    _control.Rules = r;
                    _engine.UpdateRules(r);
                }
            }
            catch (Exception ex) { _log.Write("Kural güncellemesi hatası: " + ex.Message); }
            finally { Interlocked.Exchange(ref _updateBusy, 0); }
        }
    }

    // Giris noktasi. Testler ayni derlemede kendi Main'ine sahip oldugu icin tests/guard/run.ps1
    // csc'ye /main:GuardTests verir; CortmedGuard.exe derlemesinde (Task 10) tek Main budur.
    public static class GuardProgram
    {
        static string Option(string[] args, string name)
        {
            for (int i = 0; i < args.Length - 1; i++)
                if (string.Equals(args[i], name, StringComparison.OrdinalIgnoreCase)) return args[i + 1];
            return null;
        }

        static bool Flag(string[] args, string name)
        {
            return args.Any(a => string.Equals(a, name, StringComparison.OrdinalIgnoreCase));
        }

        public static int Main(string[] args)
        {
            string dataDir = Option(args, "--data") ?? GuardService.DefaultDataDir;
            if (Flag(args, "--replay"))
            {
                try { Console.OutputEncoding = new UTF8Encoding(false); } catch { }
                string folder = Option(args, "--replay");
                if (folder == null) { Console.Error.WriteLine("Kullanım: CortmedGuard --replay <klasör> [--rules <dosya>] [--data <klasör>]"); return 2; }
                return Replay(folder, Option(args, "--rules"), dataDir);
            }
            if (Flag(args, "--console"))
            {
                try { Console.OutputEncoding = new UTF8Encoding(false); } catch { }
                var s = new GuardService(dataDir);
                try { s.StartGuard(false); }
                catch (Exception ex) { Console.Error.WriteLine("Başlatılamadı: " + ex.Message); return 1; }
                Console.WriteLine("CortmedGuard konsolda çalışıyor (" + dataDir + "). Durdurmak için Enter.");
                Console.ReadLine();
                s.StopGuard();
                return 0;
            }
            ServiceBase.Run(new GuardService(dataDir));
            return 0;
        }

        // Olaylari sirayla motora verir, Log disi her karari bir satir yazar. Hicbir surece dokunmaz;
        // gecici bir veri klasoru kullanir. --rules verilirse o dosya (dogrulamasiz, yalnizca simulasyon) kullanilir.
        static int Replay(string folder, string rulesFile, string dataDir)
        {
            string tmp = Path.Combine(Path.GetTempPath(), "CortmedGuardReplay-" + Guid.NewGuid().ToString("N"));
            Directory.CreateDirectory(tmp);
            try
            {
                var log = new GuardLog(Path.Combine(tmp, "guard.log"));
                BehaviorRules rules = rulesFile != null
                    ? BehaviorRules.Parse(File.ReadAllText(rulesFile, Encoding.UTF8))
                    : RulesStore.LoadTrusted(dataDir, RulesStore.PublicX, RulesStore.PublicY, log);
                var engine = new GuardEngine(rules, tmp, new ReplayControl(), new NoSink(), log);
                engine.DecisionMade = (d, image) =>
                    Console.WriteLine(d.Level + " kök=" + d.RootPid + " puan=" + d.Score + " " + image + " | " + string.Join("; ", d.Reasons));
                foreach (var e in GuardReplay.LoadEvents(folder)) engine.OnEvent(e);
                return 0;
            }
            catch (Exception ex)
            {
                Console.Error.WriteLine("Replay hatası: " + ex.Message);
                return 1;
            }
            finally
            {
                try { Directory.Delete(tmp, true); } catch { }
            }
        }
    }
}
