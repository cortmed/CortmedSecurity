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

        public void SendPrompt(Prompt p)
        {
            if (p == null) return;
            var d = new Dictionary<string, object>();
            d["type"] = "ask";
            d["id"] = p.Id;
            d["program"] = p.Program;
            d["path"] = p.Path;
            d["publisher"] = p.Publisher;
            d["score"] = p.Score;
            d["reasons"] = p.Reasons ?? new List<string>();
            Send(d);
        }

        public void SendStatus(bool sysmonOk, bool sysmonPreexisting)
        {
            var d = new Dictionary<string, object>();
            d["type"] = "status";
            d["sysmon"] = sysmonOk;
            d["preexisting"] = sysmonPreexisting;
            Send(d);
        }

        void Send(Dictionary<string, object> msg)
        {
            try
            {
                byte[] data = new UTF8Encoding(false).GetBytes(new JavaScriptSerializer().Serialize(msg) + "\n");
                lock (_lock)
                {
                    if (_client == null) return; // istemci yok: dusur (tekrar gonderme baska gorev)
                    try
                    {
                        Task t = _client.WriteAsync(data, 0, data.Length);
                        if (!t.Wait(2000)) throw new IOException("yazma zaman asimi");
                    }
                    catch
                    {
                        DropClientLocked();
                    }
                }
            }
            catch { }
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
