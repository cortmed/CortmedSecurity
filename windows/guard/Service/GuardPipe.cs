using System;
using System.Collections.Generic;
using System.IO;
using System.IO.Pipes;
using System.Security.AccessControl;
using System.Security.Principal;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using System.Web.Script.Serialization;

namespace Cortmed.Guard
{
    // Tepsi uygulamasina sorulan "bu program durdurulsun mu" istemi.
    public class Prompt
    {
        public string Id;
        public string Program;
        public string Path;
        public string Publisher;
        public int Score;
        public List<string> Reasons;
    }

    // SYSTEM servisi ile kullanici tepsisi arasindaki named pipe sunucusu.
    // Tek istemci; satir basina bir JSON nesnesi (UTF-8, '\n'). Gelen veri
    // guvenilmezdir: satirlar 4096 bayta sinirli, her sey dogrulanir.
    public class GuardPipe : IDisposable
    {
        const int MaxLine = 4096;

        readonly string _name;
        readonly Func<string, string, bool> _onAnswer;
        readonly ManualResetEvent _stop = new ManualResetEvent(false);
        readonly object _lock = new object();
        Thread _thread;
        NamedPipeServerStream _client; // bagli istemci (yalnizca baglantiyken dolu)
        volatile bool _disposed;

        public GuardPipe(string name, Func<string, string, bool> onAnswer)
        {
            _name = name;
            _onAnswer = onAnswer;
        }

        // Istemci baglandiginda pipe thread'inde (okuma baslamadan once) cagrilir.
        // Hizmet bekleyen sorulari ve durumu burada yeniden gonderir. Istisnalari yutulur.
        public Action Connected;

        public bool HasClient
        {
            get { lock (_lock) return _client != null; }
        }

        public void Start()
        {
            if (_thread != null) return;
            _thread = new Thread(Run);
            _thread.IsBackground = true;
            _thread.Name = "GuardPipe";
            _thread.Start();
        }

        const int MaxOut = 4096; // istemci de bu sinirdan uzun satiri atar

        static string Trunc(string s, int max)
        {
            if (s == null) return "";
            if (s.Length <= max) return s;
            int n = max - 1;
            if (n > 0 && char.IsHighSurrogate(s[n - 1])) n--;
            return s.Substring(0, n) + "\u2026";
        }

        // true: satirin tamami bagli istemciye yazildi.
        public bool SendPrompt(Prompt p)
        {
            if (p == null) return false;
            try
            {
                string id = p.Id ?? "";
                string program = Trunc(p.Program, 512);
                string path = Trunc(p.Path, 512);
                string publisher = Trunc(p.Publisher, 256);
                var reasons = new List<string>();
                if (p.Reasons != null)
                    foreach (string r in p.Reasons)
                    {
                        if (reasons.Count >= 10) break;
                        reasons.Add(Trunc(r, 256));
                    }
                var ser = new JavaScriptSerializer();
                var enc = new UTF8Encoding(false);
                while (true)
                {
                    var d = new Dictionary<string, object>();
                    d["type"] = "ask";
                    d["id"] = id;
                    d["program"] = program;
                    d["path"] = path;
                    d["publisher"] = publisher;
                    d["score"] = p.Score;
                    d["reasons"] = reasons;
                    byte[] data = enc.GetBytes(ser.Serialize(d) + "\n");
                    if (data.Length <= MaxOut) return Write(data);
                    // kucult: once yol, sonra nedenler, sonra program ve yayinci
                    if (path.Length > 16) path = Trunc(path, path.Length / 2);
                    else if (path.Length > 0) path = "";
                    else if (reasons.Count > 0) reasons.RemoveAt(reasons.Count - 1);
                    else if (program.Length > 16) program = Trunc(program, program.Length / 2);
                    else if (publisher.Length > 16) publisher = Trunc(publisher, publisher.Length / 2);
                    else if (id.Length > 64) id = id.Substring(0, 64);
                    else return false; // daha kucultulemez
                }
            }
            catch { return false; }
        }

        public void SendStatus(bool sysmonOk, bool sysmonPreexisting)
        {
            try
            {
                var d = new Dictionary<string, object>();
                d["type"] = "status";
                d["sysmon"] = sysmonOk;
                d["preexisting"] = sysmonPreexisting;
                Write(new UTF8Encoding(false).GetBytes(new JavaScriptSerializer().Serialize(d) + "\n"));
            }
            catch { }
        }

        bool Write(byte[] data)
        {
            lock (_lock)
            {
                if (_client == null) return false; // istemci yok: dusur (bekleyen istem Task 8'in isi)
                try
                {
                    Task t = _client.WriteAsync(data, 0, data.Length);
                    if (!t.Wait(2000)) throw new IOException("yazma zaman asimi");
                    return true;
                }
                catch
                {
                    DropClientLocked();
                    return false;
                }
            }
        }

        void DropClientLocked()
        {
            NamedPipeServerStream c = _client;
            _client = null;
            if (c != null) { try { c.Dispose(); } catch { } }
        }

        static PipeSecurity BuildSecurity()
        {
            var ps = new PipeSecurity();
            ps.AddAccessRule(new PipeAccessRule(new SecurityIdentifier(WellKnownSidType.LocalSystemSid, null),
                PipeAccessRights.FullControl, AccessControlType.Allow));
            ps.AddAccessRule(new PipeAccessRule(new SecurityIdentifier(WellKnownSidType.InteractiveSid, null),
                PipeAccessRights.ReadWrite, AccessControlType.Allow));
            return ps;
        }

        void Run()
        {
            while (!_disposed)
            {
                NamedPipeServerStream s = null;
                try
                {
                    s = new NamedPipeServerStream(_name, PipeDirection.InOut, 1, PipeTransmissionMode.Byte,
                        PipeOptions.Asynchronous, 4096, 4096, BuildSecurity());
                    IAsyncResult ar = s.BeginWaitForConnection(null, null);
                    int w = WaitHandle.WaitAny(new WaitHandle[] { ar.AsyncWaitHandle, _stop });
                    if (w == 1 || _disposed) { return; }
                    s.EndWaitForConnection(ar);
                    lock (_lock)
                    {
                        if (_disposed) return;
                        _client = s;
                    }
                    Action onConnected = Connected;
                    if (onConnected != null) { try { onConnected(); } catch { } }
                    ReadLoop(s);
                }
                catch
                {
                    // sunucu hicbir hatada dusmez; bir sonraki istemciyi bekler
                    if (!_disposed) _stop.WaitOne(200);
                }
                finally
                {
                    lock (_lock)
                    {
                        if (_client == s) _client = null;
                    }
                    if (s != null) { try { s.Dispose(); } catch { } }
                }
            }
        }

        void ReadLoop(NamedPipeServerStream s)
        {
            byte[] buf = new byte[1024];
            byte[] line = new byte[MaxLine];
            int len = 0;
            bool discarding = false;
            while (!_disposed)
            {
                Task<int> rt = s.ReadAsync(buf, 0, buf.Length);
                while (!rt.Wait(200))
                {
                    if (_disposed) return;
                }
                int n = rt.Result;
                if (n <= 0) return; // istemci kapandi
                for (int i = 0; i < n; i++)
                {
                    byte b = buf[i];
                    if (b == (byte)'\n')
                    {
                        if (!discarding && len > 0) HandleLine(Encoding.UTF8.GetString(line, 0, len));
                        len = 0;
                        discarding = false;
                    }
                    else if (!discarding)
                    {
                        if (len >= MaxLine) { discarding = true; len = 0; }
                        else line[len++] = b;
                    }
                }
            }
        }

        void HandleLine(string text)
        {
            try
            {
                var obj = new JavaScriptSerializer().DeserializeObject(text) as Dictionary<string, object>;
                if (obj == null) return;
                object type, id, decision;
                if (!obj.TryGetValue("type", out type) || !(type is string) || (string)type != "answer") return;
                if (!obj.TryGetValue("id", out id) || !(id is string) || ((string)id).Length == 0) return;
                if (!obj.TryGetValue("decision", out decision) || !(decision is string)) return;
                string dec = (string)decision;
                if (dec != "kill" && dec != "allow") return;
                _onAnswer((string)id, dec); // donus degeri: kabul edildi mi (cevap mesaji yok)
            }
            catch { }
        }

        public void Dispose()
        {
            if (_disposed) return;
            _disposed = true;
            try { _stop.Set(); } catch { }
            lock (_lock) { DropClientLocked(); }
            Thread t = _thread;
            if (t != null && t != Thread.CurrentThread) { try { t.Join(2000); } catch { } }
        }
    }
}
