using System;
using System.Collections;
using System.Collections.Generic;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Web.Script.Serialization;

namespace Cortmed.Guard
{
    // Surec agaci uzerindeki yetkili islemler (gercegi: RealProcessControl, testlerde sahte).
    public interface IProcessControl
    {
        // Dondurulabilenleri dondurur, dondurulenleri verir.
        List<int> FreezeTree(List<int> pids);
        void ResumeTree(List<int> pids);
        // Liste kok once verilir; yapraktan koke kapatilir.
        void KillTree(List<int> pids);
        // Surecin baslangic zamani (UTC Ticks); surec yoksa ya da okunamazsa 0. Pid yeniden kullanimi icin.
        long StartTimeOf(int pid);
    }

    // Tepsiye soru gonderen kanal. Send: true yalnizca soru istemciye tamamen ulastiysa.
    public interface IPromptSink
    {
        bool HasClient { get; }
        bool Send(Prompt p);
        // Donuk agac kendiliginden bitti: tepsideki soru geri cekilir. true: istemciye ulasti.
        bool Withdraw(string id);
    }

    // guard.log: zaman damgali UTF-8 satirlar, 1 MB'ta guard.log.1'e doner. Hicbir zaman istisna firlatmaz.
    public class GuardLog
    {
        const long MaxBytes = 1024 * 1024;
        static readonly object Gate = new object(); // ayni dosyaya yazan tum ornekler icin
        readonly string _path;

        public GuardLog(string path)
        {
            _path = path;
        }

        public string FilePath { get { return _path; } }

        public void Write(string message)
        {
            try
            {
                string line = DateTime.Now.ToString("yyyy-MM-dd HH:mm:ss", CultureInfo.InvariantCulture) + " " + Clean(message) + "\r\n";
                lock (Gate)
                {
                    var fi = new FileInfo(_path);
                    if (fi.Exists && fi.Length >= MaxBytes)
                    {
                        string old = _path + ".1";
                        if (File.Exists(old)) File.Delete(old);
                        File.Move(_path, old);
                    }
                    File.AppendAllText(_path, line, new UTF8Encoding(false));
                }
            }
            catch { }
        }

        // Kayit enjeksiyonuna karsi: satir sonlari ve kontrol karakterleri bosluga cevrilir.
        static string Clean(string s)
        {
            if (s == null) return "";
            s = s.Replace("\r\n", "\n");
            var sb = new StringBuilder(s.Length);
            foreach (char ch in s) sb.Append(char.IsControl(ch) ? ' ' : ch);
            return sb.ToString();
        }
    }

    // Gecici dosyaya yazip yerine koyar; okuyan (tepsi) yarim dosya gormez.
    public static class AtomicFile
    {
        public static void WriteAllBytes(string path, byte[] data)
        {
            string tmp = path + ".tmp";
            File.WriteAllBytes(tmp, data);
            if (File.Exists(path))
            {
                try { File.Replace(tmp, path, null); return; }
                catch (IOException) { }
                catch (UnauthorizedAccessException) { }
                File.Copy(tmp, path, true);
                File.Delete(tmp);
            }
            else File.Move(tmp, path);
        }

        public static void WriteAllText(string path, string text)
        {
            WriteAllBytes(path, new UTF8Encoding(false).GetBytes(text));
        }
    }

    public static class Hashing
    {
        public static string Hex(byte[] b)
        {
            var sb = new StringBuilder(b.Length * 2);
            foreach (byte x in b) sb.Append(x.ToString("X2", CultureInfo.InvariantCulture));
            return sb.ToString();
        }

        public static string Sha256(byte[] data)
        {
            using (var h = SHA256.Create()) return Hex(h.ComputeHash(data));
        }

        // Dosyanin SHA-256'si (buyuk harf); okunamazsa "".
        public static string Sha256File(string path)
        {
            try
            {
                if (string.IsNullOrEmpty(path) || !File.Exists(path)) return "";
                using (var fs = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete))
                using (var h = SHA256.Create())
                    return Hex(h.ComputeHash(fs));
            }
            catch { return ""; }
        }

        public static bool IsSha256Hex(string s)
        {
            if (s == null || s.Length != 64) return false;
            foreach (char c in s)
                if (!((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F'))) return false;
            return true;
        }
    }

    // findings.json: tepsinin okudugu bulgu dizisi {key, level, title, detail, path, tab, report}.
    // En yeni basta; anahtara gore guncellenir; en fazla 200 kayit.
    public static class FindingStore
    {
        const int Max = 200;

        static JavaScriptSerializer Serializer()
        {
            var s = new JavaScriptSerializer();
            s.MaxJsonLength = int.MaxValue;
            return s;
        }

        public static List<Dictionary<string, object>> Read(string file)
        {
            var list = new List<Dictionary<string, object>>();
            if (!File.Exists(file)) return list;
            string text = File.ReadAllText(file, Encoding.UTF8);
            if (text.Trim().Length == 0) return list;
            var arr = Serializer().DeserializeObject(text) as object[];
            if (arr == null) throw new InvalidDataException("findings.json bir dizi değil");
            foreach (object o in arr)
            {
                var d = o as Dictionary<string, object>;
                if (d != null) list.Add(d);
            }
            return list;
        }

        public static void Upsert(string file, Dictionary<string, object> finding)
        {
            List<Dictionary<string, object>> list;
            try { list = Read(file); }
            catch { list = new List<Dictionary<string, object>>(); } // bozuk dosya: bastan yaz
            string key = Convert.ToString(finding["key"]);
            list.RemoveAll(f =>
            {
                object k;
                return f.TryGetValue("key", out k) && Convert.ToString(k) == key;
            });
            list.Insert(0, finding);
            if (list.Count > Max) list.RemoveRange(Max, list.Count - Max);
            AtomicFile.WriteAllText(file, Serializer().Serialize(list));
        }
    }

    /// <summary>
    /// Davranis bekcisinin saf mantigi: olay -> surec agaci -> siniflandirici -> puan -> karar.
    /// Freeze: koke ait agac dondurulur, bekleyen soru (pending.json) olusur, tepsiye gonderilir.
    /// Thread-safe: tum durum tek kilit (_lock) altindadir. IProcessControl cagrilari kilit altinda
    /// yapilir: gercek uygulama yalnizca kisa, bekletmeyen sistem cagrilari yapar (OpenProcess,
    /// NtSuspend/Resume, TerminateProcess) ve kilit, dondurma ile bekleyen kaydin olusmasi arasinda
    /// yeni bir cocuk surecin kacmamasini garanti eder. IPromptSink.Send (2 sn'ye kadar bekleyebilir)
    /// hicbir zaman _lock altinda cagrilmaz; gonderimler ayri _sendLock ile siralanir.
    /// Kok imajinin SHA-256'si Sysmon olayinda yoksa dosyadan kilit altinda hesaplanir (kok basina bir kez);
    /// FileTrust.BaseScore (kok basina bir kez) ve FileTrust.Publisher (yalnizca karar aninda) ve yazanin imzasi (I7, imaj basina bir kez) da kilit
    /// altindadir. Bunlar olay islemeyi kisa sure bekletebilir; olaylar kaybolmaz, threadpool'da sirayla bekler.
    /// </summary>
    public class GuardEngine
    {
        class Pending
        {
            public Prompt Prompt;
            public int Root;
            public string Hash = "";
            public List<int> Pids = new List<int>();
            public List<long> Starts = new List<long>();
            public int SentGeneration; // bu baglanti neslinde gonderildi mi
            public int PidsOnDisk;     // pending.json'dan yuklenirken kayitli pid sayisi
        }

        readonly object _lock = new object();
        readonly object _sendLock = new object();
        readonly string _dataDir;
        readonly IProcessControl _control;
        readonly IPromptSink _sink;
        readonly GuardLog _log;
        readonly ProcessTree _tree;
        volatile BehaviorRules _rules;
        Classifier _classifier;
        ScoreBoard _board;
        readonly Dictionary<int, int> _baseScores = new Dictionary<int, int>();
        readonly Dictionary<int, string> _rootHash = new Dictionary<int, string>();
        readonly Dictionary<int, string> _rootPublisher = new Dictionary<int, string>(); // WinVerifyTrust kok basina bir kez
        readonly Dictionary<int, int> _lastWarnScore = new Dictionary<int, int>(); // ayni puanda tekrar bulgu/kayit yazma
        readonly Dictionary<string, Pending> _pending = new Dictionary<string, Pending>();
        readonly Dictionary<int, Pending> _byRoot = new Dictionary<int, Pending>(); // canli izlenen donuk kokler
        readonly HashSet<string> _allowed = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        int _generation = 1;

        // Log disi her karar icin (kilit disinda) cagrilir: karar ve kok imaj yolu. --replay ciktisi icin.
        public Action<Decision, string> DecisionMade;

        public GuardEngine(BehaviorRules r, string dataDir, IProcessControl control, IPromptSink sink)
            : this(r, dataDir, control, sink, null) { }

        public GuardEngine(BehaviorRules r, string dataDir, IProcessControl control, IPromptSink sink, GuardLog log)
        {
            if (r == null) throw new ArgumentNullException("r");
            if (control == null) throw new ArgumentNullException("control");
            if (sink == null) throw new ArgumentNullException("sink");
            _dataDir = dataDir;
            Directory.CreateDirectory(dataDir);
            _control = control;
            _sink = sink;
            _log = log ?? new GuardLog(Path.Combine(dataDir, "guard.log"));
            // Tarayici, Discord, arsivci ve Windows hizmet sureclerinin cocuklari kendi agaclarini baslatir;
            // puan, suc ve dondurma baslatana degil, asil programa yazilir.
            _tree = new ProcessTree(img => PathRules.IsRootStarter(img, _rules, KnownFolders.Current));
            SetRules(r);
            LoadAllowed();
            LoadPending();
        }

        string DataFile(string name) { return Path.Combine(_dataDir, name); }

        // Imza denetimi (varsayilan FileTrust.IsValidlySigned); testler degistirebilir. Sonuc imaj yoluna gore
        // onbellekte tutulur (calisan surecin dosyasi kilitlidir); onbellek 512 kayitta bosaltilir. _lock altinda cagrilir.
        public Func<string, bool> SignatureCheck = FileTrust.IsValidlySigned;
        readonly Dictionary<string, bool> _signed = new Dictionary<string, bool>(StringComparer.OrdinalIgnoreCase);

        bool IsSignedCached(string image)
        {
            if (string.IsNullOrEmpty(image)) return false;
            bool v;
            if (_signed.TryGetValue(image, out v)) return v;
            var check = SignatureCheck;
            try { v = check != null && check(image); } catch { v = false; }
            if (_signed.Count >= 512) _signed.Clear();
            _signed[image] = v;
            return v;
        }

        void SetRules(BehaviorRules r)
        {
            _rules = r;
            _classifier = new Classifier(r, KnownFolders.Current, IsSignedCached);
            _board = new ScoreBoard(r);
            _baseScores.Clear();
            _lastWarnScore.Clear();
        }

        // Imzasi dogrulanmis yeni kurallar. Puan tahtasi sifirlanir; bekleyen sorular korunur.
        public void UpdateRules(BehaviorRules r)
        {
            if (r == null) return;
            lock (_lock)
            {
                SetRules(r);
                _log.Write("Davranış kuralları güncellendi (dondurma eşiği " + r.FreezeAt + ", uyarı eşiği " + r.WarnAt + ").");
            }
        }

        public int PendingCount
        {
            get { lock (_lock) return _pending.Count; }
        }

        // ---- olaylar ----

        public void OnEvent(GuardEvent e)
        {
            if (e == null) return;
            var decisions = new List<KeyValuePair<Decision, string>>();
            var withdrawn = new List<string>();
            bool flush = false;
            lock (_lock)
            {
                try { flush = Process(e, decisions, withdrawn); }
                catch (Exception ex) { _log.Write("Olay işlenemedi (olay " + e.EventId + ", pid " + e.Pid + "): " + ex.Message); }
            }
            var cb = DecisionMade;
            if (cb != null)
                foreach (var kv in decisions)
                {
                    try { cb(kv.Key, kv.Value); } catch { }
                }
            if (withdrawn.Count > 0) SendWithdrawn(withdrawn);
            if (flush) FlushPending();
        }

        // _lock DISINDA cagrilir (kilit sirasi: _sendLock -> _lock; sink asla _lock altinda cagrilmaz)
        void SendWithdrawn(List<string> ids)
        {
            lock (_sendLock)
            {
                foreach (string id in ids)
                {
                    try { _sink.Withdraw(id); } catch { }
                }
            }
        }

        bool Process(GuardEvent e, List<KeyValuePair<Decision, string>> decisions, List<string> withdrawn)
        {
            bool flush = false;
            DateTime now = e.Time == default(DateTime) ? DateTime.UtcNow : e.Time;

            if (e.EventId == 1)
            {
                _tree.OnProcessStart(e);
                int root = _tree.RootOf(e.Pid);
                if (root == e.Pid)
                {
                    // yeni kok (pid yeniden kullanimi dahil): eski puan/donuk kayit bu pid'e gecmesin
                    ForgetRoot(root);
                    string h = SysmonReader.Sha256Of(e.Hashes);
                    if (Hashing.IsSha256Hex(h)) _rootHash[root] = h;
                }
                else
                {
                    Pending p;
                    if (_byRoot.TryGetValue(root, out p)) FreezeLate(p, e);
                }
            }
            else if (e.EventId == 5)
            {
                int gone = _tree.OnProcessExit(e.Pid);
                if (gone != 0)
                {
                    Pending p;
                    if (_byRoot.TryGetValue(gone, out p))
                    {
                        _pending.Remove(p.Prompt.Id);
                        withdrawn.Add(p.Prompt.Id);
                        SavePending();
                        _log.Write("Donuk ağaç kendiliğinden sona erdi, soru kaldırıldı: " + p.Prompt.Path + " (kök " + gone + ")");
                    }
                    ForgetRoot(gone);
                }
            }

            foreach (var hit in _classifier.Classify(e))
            {
                int root = _tree.RootOf(hit.Pid);
                string image = ImageFor(root, e);
                var d = _board.Add(root, BaseScoreOf(root, image), hit, now);
                if (Handle(d, image, decisions)) flush = true;
            }

            if (_classifier.CountsAsDocumentWrite(e))
            {
                int root = _tree.RootOf(e.Pid);
                string image = ImageFor(root, e);
                var d = _board.AddDocumentWrite(root, BaseScoreOf(root, image), now);
                if (Handle(d, image, decisions)) flush = true;
            }
            return flush;
        }

        // ScoreBoard sozlesmesi: kok bittiginde ya da pid yeni bir kok oldugunda Forget.
        void ForgetRoot(int root)
        {
            _board.Forget(root);
            _baseScores.Remove(root);
            _rootHash.Remove(root);
            _rootPublisher.Remove(root);
            _lastWarnScore.Remove(root);
            // Bekleyen soru (varsa) cevaplanabilir kalir ama bu pid'in yeni agaci donuk sayilmaz.
            _byRoot.Remove(root);
        }

        string ImageFor(int root, GuardEvent e)
        {
            string img = _tree.ImageOf(root);
            if (string.IsNullOrEmpty(img))
            {
                if (root == e.Pid) img = e.Image;
                else if (root == e.ParentPid) img = e.ParentImage;
            }
            return img ?? "";
        }

        int BaseScoreOf(int root, string image)
        {
            int s;
            if (_baseScores.TryGetValue(root, out s)) return s;
            s = FileTrust.BaseScore(image, _rules);
            _baseScores[root] = s;
            return s;
        }

        string HashOf(int root, string image)
        {
            string h;
            if (_rootHash.TryGetValue(root, out h) && h.Length > 0) return h;
            h = Hashing.Sha256File(image);
            if (h.Length > 0) _rootHash[root] = h;
            return h;
        }

        string PublisherOf(int root, string image)
        {
            string p;
            if (_rootPublisher.TryGetValue(root, out p)) return p;
            p = FileTrust.Publisher(image) ?? "";
            _rootPublisher[root] = p;
            return p;
        }

        // Ayni kok icin Warn/izinli kaydi yalnizca puan son kayittan yuksekse yazilir.
        bool WarnScoreRose(int root, int score)
        {
            int last;
            if (_lastWarnScore.TryGetValue(root, out last) && score <= last) return false;
            _lastWarnScore[root] = score;
            return true;
        }

        // %windir%\System32 ve SysWOW64 altindaki Microsoft araclari (wscript, mshta, powershell...)
        // kalici izin listesine alinmaz: tek seferlik izin verilir.
        public static bool IsSystemBinary(string path)
        {
            if (string.IsNullOrEmpty(path)) return false;
            string win = Environment.GetEnvironmentVariable("SystemRoot");
            if (string.IsNullOrEmpty(win)) win = Environment.GetFolderPath(Environment.SpecialFolder.Windows);
            if (string.IsNullOrEmpty(win)) return false;
            win = win.TrimEnd('\\') + "\\";
            foreach (string sub in new[] { "System32\\", "SysWOW64\\" })
                if (path.StartsWith(win + sub, StringComparison.OrdinalIgnoreCase)) return true;
            return false;
        }

        static string FileName(string path)
        {
            if (string.IsNullOrEmpty(path)) return "";
            int i = path.LastIndexOfAny(new[] { '\\', '/' });
            return i >= 0 ? path.Substring(i + 1) : path;
        }

        // true: yeni bekleyen soru olustu (gonderilmeli).
        bool Handle(Decision d, string image, List<KeyValuePair<Decision, string>> decisions)
        {
            if (d.Level == DecisionLevel.Log) return false;
            decisions.Add(new KeyValuePair<Decision, string>(d, image));
            int root = d.RootPid;
            string reasons = string.Join(" ", d.Reasons);
            if (_byRoot.ContainsKey(root)) return false; // zaten donuk, soru bekliyor

            string hash = HashOf(root, image);
            if (hash.Length > 0 && _allowed.Contains(hash))
            {
                if (d.Level == DecisionLevel.Warn && !WarnScoreRose(root, d.Score)) return false;
                _log.Write("İzin verilmiş program, işlem yapılmadı: " + image + " (puan " + d.Score + ") " + reasons);
                return false;
            }

            if (d.Level == DecisionLevel.Warn)
            {
                if (!WarnScoreRose(root, d.Score)) return false;
                _log.Write("Şüpheli davranış (puan " + d.Score + "): " + image + " (kök " + root + ") " + reasons);
                RecordFinding("YELLOW", image, hash, PublisherOf(root, image), d.Score, d.Reasons, "Program durdurulmadı; şüpheli davranış kaydedildi.");
                return false;
            }

            // Freeze
            // Imaji bilinen korumali surecler (taban liste, kurallar, Windows hizmet surecleri) hic
            // FreezeTree'ye verilmez; kok korumaliysa agacin hicbir parcasi dondurulmaz (soru koku adlandirir).
            // Canli denetim (oturum 0, tam yol) ayrica ProcessControl.CanFreeze'dedir.
            var order = new List<int>();
            if (string.IsNullOrEmpty(image) || !ProcessControl.IsProtectedImage(image, _rules))
            {
                order.Add(root);
                foreach (int pid in _tree.Subtree(root))
                {
                    if (pid == root) continue;
                    string img = _tree.ImageOf(pid);
                    if (!string.IsNullOrEmpty(img) && ProcessControl.IsProtectedImage(img, _rules)) continue;
                    order.Add(pid);
                }
            }
            List<int> frozen = order.Count == 0 ? new List<int>() : (_control.FreezeTree(new List<int>(order)) ?? new List<int>());
            if (frozen.Count == 0)
            {
                _log.Write("Dondurma eşiği aşıldı ama ağaçta dondurulabilen süreç yok: " + image + " (puan " + d.Score + ") " + reasons);
                RecordFinding("YELLOW", image, hash, PublisherOf(root, image), d.Score, d.Reasons, "Program dondurulamadı; şüpheli davranış kaydedildi.");
                return false;
            }

            var p = new Pending();
            p.Root = root;
            p.Hash = hash;
            p.Prompt = new Prompt
            {
                Id = Guid.NewGuid().ToString("N"),
                Program = FileName(image),
                Path = image,
                Publisher = PublisherOf(root, image),
                Score = d.Score,
                Reasons = new List<string>(d.Reasons)
            };
            foreach (int pid in order)
            {
                if (!frozen.Contains(pid)) continue;
                p.Pids.Add(pid);
                p.Starts.Add(_control.StartTimeOf(pid));
            }
            _pending[p.Prompt.Id] = p;
            _byRoot[root] = p;
            SavePending();
            _log.Write("Ağaç donduruldu, kullanıcıya soruluyor: " + image + " (puan " + d.Score + ", süreçler "
                + string.Join(",", p.Pids) + ") " + reasons);
            return true;
        }

        void FreezeLate(Pending p, GuardEvent e)
        {
            List<int> got = _control.FreezeTree(new List<int> { e.Pid }) ?? new List<int>();
            foreach (int pid in got)
            {
                if (p.Pids.Contains(pid)) continue;
                p.Pids.Add(pid);
                p.Starts.Add(_control.StartTimeOf(pid));
            }
            if (got.Count > 0) SavePending();
            _log.Write("Donuk ağaçta yeni süreç " + (got.Count > 0 ? "donduruldu" : "dondurulamadı") + ": " + e.Image + " (pid " + e.Pid + ")");
        }

        // ---- cevaplar ----

        // GuardPipe onAnswer geri cagrisina dogrudan baglanir. false: bekleyen soru yok ya da karar gecersiz.
        public bool OnAnswer(string id, string decision)
        {
            if (string.IsNullOrEmpty(id) || (decision != "kill" && decision != "allow")) return false;
            lock (_lock)
            {
                Pending p;
                if (!_pending.TryGetValue(id, out p)) return false;
                try
                {
                    _pending.Remove(id);
                    Pending cur;
                    bool tracked = _byRoot.TryGetValue(p.Root, out cur) && cur == p;
                    if (tracked) _byRoot.Remove(p.Root);
                    SavePending();

                    if (decision == "kill")
                    {
                        var live = Live(p, true);
                        _control.KillTree(live);
                        _log.Write("Kullanıcı kapatmayı seçti: " + p.Prompt.Path + " (kapatılan " + string.Join(",", live) + ")");
                        RecordFinding("RED", p.Prompt.Path, p.Hash, p.Prompt.Publisher ?? "", p.Prompt.Score, p.Prompt.Reasons,
                            "Program sizin onayınızla kapatıldı. Dosyaya dokunulmadı.");
                    }
                    else
                    {
                        var live = Live(p, false);
                        _control.ResumeTree(live);
                        if (IsSystemBinary(p.Prompt.Path))
                            _log.Write("Windows sistem aracı yalnızca bu sefer için izinli; izin listesine eklenmedi: " + p.Prompt.Path);
                        else if (Hashing.IsSha256Hex(p.Hash)) AddAllowed(p.Hash);
                        else _log.Write("Dosya parmak izi bilinmiyor; izin listesine eklenemedi: " + p.Prompt.Path);
                        if (tracked)
                        {
                            _board.Forget(p.Root);
                            _baseScores.Remove(p.Root);
                        }
                        _log.Write("Kullanıcı izin verdi: " + p.Prompt.Path + " (devam ettirilen " + string.Join(",", live) + ")");
                    }
                }
                catch (Exception ex)
                {
                    _log.Write("Cevap işlenirken hata: " + ex.Message);
                }
                return true;
            }
        }

        // Baslangic zamani kayittakiyle ayni olan pid'ler (pid yeniden kullanimina karsi).
        // strict (kapatma): kayitli zaman yoksa da atlanir.
        List<int> Live(Pending p, bool strict)
        {
            var res = new List<int>();
            for (int i = 0; i < p.Pids.Count; i++)
            {
                long rec = p.Starts[i];
                long now = _control.StartTimeOf(p.Pids[i]);
                bool ok = rec != 0 ? now == rec : !strict;
                if (ok) res.Add(p.Pids[i]);
                else _log.Write("Süreç değişmiş ya da bitmiş, atlandı: pid " + p.Pids[i]);
            }
            return res;
        }

        // ---- tepsi ----

        public void OnClientConnected()
        {
            lock (_lock) { _generation++; }
            FlushPending();
        }

        void FlushPending()
        {
            lock (_sendLock)
            {
                List<Pending> todo;
                int gen;
                lock (_lock)
                {
                    gen = _generation;
                    todo = _pending.Values.Where(x => x.SentGeneration != gen).ToList();
                }
                if (todo.Count == 0) return;
                bool client;
                try { client = _sink.HasClient; } catch { client = false; }
                if (!client) return;
                foreach (var p in todo)
                {
                    bool ok;
                    try { ok = _sink.Send(p.Prompt); } catch { ok = false; }
                    if (!ok) break; // kalanlar bir sonraki baglantida
                    lock (_lock) { p.SentGeneration = gen; }
                }
            }
        }

        // ---- kalici dosyalar ----

        void RecordFinding(string level, string image, string hash, string publisher, int score, List<string> reasons, string note)
        {
            try
            {
                string name = FileName(image);
                if (name.Length == 0) name = "bilinmeyen program";
                var report = new StringBuilder();
                report.AppendLine("Program: " + image);
                report.AppendLine("Yayıncı: " + (publisher.Length > 0 ? publisher : "bilinmiyor (imzasız)"));
                report.AppendLine("Davranış puanı: " + score);
                if (hash.Length > 0) report.AppendLine("SHA-256: " + hash);
                report.AppendLine("Nedenler:");
                foreach (string r in reasons) report.AppendLine("- " + r);
                report.AppendLine(note);

                var f = new Dictionary<string, object>();
                f["key"] = hash.Length > 0 ? "behavior:" + hash : "behavior:path:" + image.ToLowerInvariant();
                f["level"] = level;
                f["title"] = (level == "RED" ? "Durdurulan program: " : "Şüpheli davranış: ") + name;
                f["detail"] = string.Join(" ", reasons) + (level == "RED" ? "" : " " + note);
                f["path"] = image;
                f["tab"] = "threat";
                f["report"] = report.ToString();
                f["time"] = DateTime.UtcNow.ToString("o");
                FindingStore.Upsert(DataFile("findings.json"), f);
            }
            catch (Exception ex)
            {
                _log.Write("findings.json yazılamadı: " + ex.Message);
            }
        }

        void LoadAllowed()
        {
            try
            {
                string path = DataFile("allowed.txt");
                if (!File.Exists(path)) return;
                foreach (string line in File.ReadAllLines(path, Encoding.UTF8))
                {
                    string h = line.Trim().ToUpperInvariant();
                    if (Hashing.IsSha256Hex(h)) _allowed.Add(h);
                }
            }
            catch (Exception ex) { _log.Write("allowed.txt okunamadı: " + ex.Message); }
        }

        void AddAllowed(string hash)
        {
            string h = hash.ToUpperInvariant();
            if (!_allowed.Add(h)) return;
            try { File.AppendAllText(DataFile("allowed.txt"), h + "\r\n", new UTF8Encoding(false)); }
            catch (Exception ex) { _log.Write("allowed.txt yazılamadı: " + ex.Message); }
        }

        void SavePending()
        {
            try
            {
                var list = new List<object>();
                foreach (var p in _pending.Values)
                {
                    var d = new Dictionary<string, object>();
                    d["id"] = p.Prompt.Id;
                    d["root"] = p.Root;
                    d["hash"] = p.Hash;
                    d["program"] = p.Prompt.Program;
                    d["path"] = p.Prompt.Path;
                    d["publisher"] = p.Prompt.Publisher;
                    d["score"] = p.Prompt.Score;
                    d["reasons"] = p.Prompt.Reasons;
                    d["pids"] = p.Pids;
                    d["starts"] = p.Starts.Select(s => s.ToString(CultureInfo.InvariantCulture)).ToList();
                    list.Add(d);
                }
                var ser = new JavaScriptSerializer();
                ser.MaxJsonLength = int.MaxValue;
                AtomicFile.WriteAllText(DataFile("pending.json"), ser.Serialize(list));
            }
            catch (Exception ex) { _log.Write("pending.json yazılamadı: " + ex.Message); }
        }

        // Yeniden baslamada: surecleri hala ayni olan kayitlar geri yuklenir, surecleri bitenler atilir.
        // Her kayit ayri ayristirilir: bozuk kayit atlanir (dosyanin ozgun hali pending.json.bad'e
        // yedeklenir), digerleri korunur. Dosyanin tamami okunamazsa pending.json.bad'e tasinir ve
        // ustune bos kayit yazilmaz.
        // Geri yuklenen kayitlar _byRoot'a eklenmez (agac bilgisi yeni; donuk surecler cocuk baslatamaz).
        void LoadPending()
        {
            string path = DataFile("pending.json");
            if (!File.Exists(path)) return;
            object[] arr;
            try
            {
                var ser = new JavaScriptSerializer();
                ser.MaxJsonLength = int.MaxValue;
                arr = ser.DeserializeObject(File.ReadAllText(path, Encoding.UTF8)) as object[];
                if (arr == null) throw new InvalidDataException("dizi değil");
            }
            catch (Exception ex)
            {
                _log.Write("pending.json okunamadı (" + ex.Message + "); pending.json.bad olarak saklanıyor.");
                MoveToBad(path, true);
                return;
            }

            bool changed = false, corrupt = false;
            for (int n = 0; n < arr.Length; n++)
            {
                try
                {
                    var p = ParsePending(arr[n]);
                    if (p.Pids.Count == 0)
                    {
                        _log.Write("Bekleyen sorunun süreçleri artık yok, kaldırıldı: " + p.Prompt.Path);
                        changed = true;
                        continue;
                    }
                    if (p.Pids.Count != p.PidsOnDisk) changed = true;
                    _pending[p.Prompt.Id] = p;
                }
                catch (Exception ex)
                {
                    _log.Write("pending.json kaydı " + n + " bozuk, atlandı: " + ex.Message);
                    corrupt = true;
                }
            }
            if (corrupt) MoveToBad(path, false); // ozgun dosyanin kopyasi kalir
            if (changed || corrupt) SavePending();
            if (_pending.Count > 0) _log.Write(_pending.Count + " bekleyen soru geri yüklendi.");
        }

        void MoveToBad(string path, bool move)
        {
            try
            {
                string bad = path + ".bad";
                if (File.Exists(bad)) File.Delete(bad);
                if (move) File.Move(path, bad);
                else File.Copy(path, bad);
            }
            catch (Exception ex) { _log.Write("pending.json.bad yazılamadı: " + ex.Message); }
        }

        Pending ParsePending(object o)
        {
            var d = o as Dictionary<string, object>;
            if (d == null) throw new InvalidDataException("nesne değil");
            var p = new Pending();
            p.Root = ToInt(Get(d, "root"));
            p.Hash = Convert.ToString(Get(d, "hash") ?? "");
            p.Prompt = new Prompt
            {
                Id = Convert.ToString(Get(d, "id") ?? ""),
                Program = Convert.ToString(Get(d, "program") ?? ""),
                Path = Convert.ToString(Get(d, "path") ?? ""),
                Publisher = Convert.ToString(Get(d, "publisher") ?? ""),
                Score = ToInt(Get(d, "score")),
                Reasons = new List<string>()
            };
            if (p.Prompt.Id.Length == 0) throw new InvalidDataException("id yok");
            var reasons = Get(d, "reasons") as object[];
            if (reasons != null) foreach (object r in reasons) p.Prompt.Reasons.Add(Convert.ToString(r));
            var pids = Get(d, "pids") as object[];
            var starts = Get(d, "starts") as object[];
            if (pids == null || starts == null || pids.Length != starts.Length) throw new InvalidDataException("pids/starts geçersiz");
            var recs = new long[pids.Length];
            for (int i = 0; i < pids.Length; i++)
                recs[i] = long.Parse(Convert.ToString(starts[i], CultureInfo.InvariantCulture), NumberStyles.Integer, CultureInfo.InvariantCulture);
            p.PidsOnDisk = pids.Length;
            for (int i = 0; i < pids.Length; i++)
            {
                int pid = Convert.ToInt32(pids[i], CultureInfo.InvariantCulture);
                if (recs[i] != 0 && _control.StartTimeOf(pid) == recs[i])
                {
                    p.Pids.Add(pid);
                    p.Starts.Add(recs[i]);
                }
            }
            return p;
        }

        static object Get(Dictionary<string, object> d, string k)
        {
            object v;
            return d.TryGetValue(k, out v) ? v : null;
        }

        static int ToInt(object v)
        {
            try { return v == null ? 0 : Convert.ToInt32(v, CultureInfo.InvariantCulture); }
            catch { return 0; }
        }
    }
}
