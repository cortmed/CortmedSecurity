// Cortmed tarayici koprusu (Chrome / Edge yerel mesajlasma, stdio).
// Eklentiden tek bir dosya yolu alir ({"path": "..."}), yolu dogrular, dosyayi
// CortmedSecurity.ps1 -Mode ScanFile -Json ile tarar ve {level,title,reasons} dondurur.
// Komut almaz; her surec tek bir istegi isler ve cikar.
// C# 5 (csc v4). Derleme: /codepage:65001 /reference:System.Web.Extensions.dll
// Yalnizca testler icin: --scan-cmd <exe> [args...] (tarama komutu), --data <klasor> (browser-lastseen.txt yeri).
using System;
using System.Collections;
using System.Collections.Generic;
using System.Diagnostics;
using System.Globalization;
using System.IO;
using System.Text;
using System.Threading;
using System.Web.Script.Serialization;

namespace Cortmed.Browser
{
    public static class BrowserHost
    {
        const int MaxMessage = 65536;
        const int ScanTimeoutMs = 120000;
        const int MaxText = 200;
        const int MaxReasons = 5;
        const int MaxKeptLines = 64;

        const string TitleBadRequest = "İstek okunamadı";
        const string TitleBadSize = "İstek çok büyük ya da boş";
        const string TitleBadPath = "Geçersiz dosya yolu";
        const string TitleOutside = "Bu konumdaki dosyalar taranmaz";
        const string TitleMissing = "Dosya bulunamadı";
        const string TitleReparse = "Bu dosya taranamıyor";
        const string TitleNoStart = "Tarama başlatılamadı";
        const string TitleTimeout = "Tarama zaman aşımına uğradı";
        const string TitleBadOutput = "Tarama sonucu okunamadı";
        const string TitleScanFailed = "Dosya taranamadı";
        const string TitleUnexpected = "Beklenmeyen bir hata oluştu";

        public static int Main(string[] args)
        {
            Stream output = null;
            bool replied = false;
            try
            {
                output = Console.OpenStandardOutput();
                string scanExe = null;
                List<string> scanArgs = new List<string>();
                string dataDir = null;
                ParseArgs(args, ref scanExe, scanArgs, ref dataDir);
                if (dataDir == null)
                {
                    dataDir = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "CortmedSecurity", "data");
                }
                Dictionary<string, object> reply = Handle(Console.OpenStandardInput(), scanExe, scanArgs, dataDir);
                replied = true;
                WriteMessage(output, reply);
            }
            catch (Exception)
            {
                if (!replied && output != null)
                {
                    try { WriteMessage(output, Error(TitleUnexpected)); } catch (Exception) { }
                }
            }
            return 0;
        }

        // Chrome kendi baglantisini (kaynak adresi, --parent-window) da gecirir; bilinmeyenler yok sayilir.
        static void ParseArgs(string[] args, ref string scanExe, List<string> scanArgs, ref string dataDir)
        {
            for (int i = 0; i < args.Length; i++)
            {
                if (args[i] == "--data" && i + 1 < args.Length)
                {
                    dataDir = args[++i];
                }
                else if (args[i] == "--scan-cmd" && i + 1 < args.Length)
                {
                    scanExe = args[++i];
                    while (i + 1 < args.Length && args[i + 1] != "--data") scanArgs.Add(args[++i]);
                }
            }
        }

        static Dictionary<string, object> Handle(Stream input, string scanExe, List<string> scanArgs, string dataDir)
        {
            byte[] header = ReadExactly(input, 4);
            if (header == null) return Error(TitleBadRequest);
            uint length = (uint)(header[0] | (header[1] << 8) | (header[2] << 16) | (header[3] << 24));
            // Govde okunmadan reddedilir
            if (length == 0 || length > MaxMessage) return Error(TitleBadSize);
            byte[] body = ReadExactly(input, (int)length);
            if (body == null) return Error(TitleBadRequest);

            string path;
            try
            {
                string text = new UTF8Encoding(false, true).GetString(body);
                IDictionary<string, object> obj = new JavaScriptSerializer().DeserializeObject(text) as IDictionary<string, object>;
                object value;
                if (obj == null || !obj.TryGetValue("path", out value)) return Error(TitleBadRequest);
                path = value as string;
                if (path == null) return Error(TitleBadRequest);
            }
            catch (Exception)
            {
                return Error(TitleBadRequest);
            }

            // Eklenti kopruye ulasti: panel "Tarayici korumasi acik" gosterebilsin (yol hatali olsa da)
            TouchLastSeen(dataDir);

            string full;
            string why = ValidatePath(path, out full);
            if (why != null) return Error(why);
            return RunScan(full, scanExe, scanArgs);
        }

        static byte[] ReadExactly(Stream s, int count)
        {
            byte[] buf = new byte[count];
            int got = 0;
            while (got < count)
            {
                int n = s.Read(buf, got, count - got);
                if (n <= 0) return null;
                got += n;
            }
            return buf;
        }

        static void TouchLastSeen(string dataDir)
        {
            try
            {
                Directory.CreateDirectory(dataDir);
                File.WriteAllText(Path.Combine(dataDir, "browser-lastseen.txt"),
                    DateTime.UtcNow.ToString("yyyy-MM-dd'T'HH:mm:ss'Z'", CultureInfo.InvariantCulture));
            }
            catch (Exception) { }
        }

        static bool IsDriveLetter(char c)
        {
            return (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z');
        }

        // null = gecerli; aksi halde kullaniciya gosterilecek Turkce neden
        static string ValidatePath(string path, out string full)
        {
            full = null;
            if (string.IsNullOrEmpty(path)) return TitleBadPath;
            if (path.IndexOf('"') >= 0 || path.IndexOf('\0') >= 0) return TitleBadPath;
            if (path.StartsWith(@"\\?\", StringComparison.Ordinal) || path.StartsWith(@"\\.\", StringComparison.Ordinal) ||
                path.StartsWith(@"\??\", StringComparison.Ordinal)) return TitleBadPath;
            if (path.StartsWith(@"\\", StringComparison.Ordinal) || path.StartsWith("//", StringComparison.Ordinal) ||
                path.StartsWith(@"\/", StringComparison.Ordinal) || path.StartsWith(@"/\", StringComparison.Ordinal)) return TitleOutside;
            // Tam yol olmali ("X:\..."); goreli, surucu-goreli ve ikinci ':' (alternatif veri akisi) reddedilir
            if (path.Length < 3 || !IsDriveLetter(path[0]) || path[1] != ':' || (path[2] != '\\' && path[2] != '/') ||
                path.IndexOf(':', 2) >= 0) return TitleBadPath;
            try { full = Path.GetFullPath(path); }
            catch (Exception) { full = null; return TitleBadPath; }

            string profile = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);
            if (string.IsNullOrEmpty(profile)) return TitleOutside;
            profile = profile.TrimEnd('\\') + "\\";
            if (!full.StartsWith(profile, StringComparison.OrdinalIgnoreCase)) return TitleOutside;
            if (!File.Exists(full)) return TitleMissing;
            FileAttributes attr;
            try { attr = File.GetAttributes(full); }
            catch (Exception) { return TitleMissing; }
            if ((attr & FileAttributes.ReparsePoint) != 0) return TitleReparse;
            return null;
        }

        static Dictionary<string, object> RunScan(string full, string scanExe, List<string> scanArgs)
        {
            string hostDir = AppDomain.CurrentDomain.BaseDirectory;
            string exe;
            List<string> a = new List<string>();
            if (scanExe != null)
            {
                exe = scanExe;
                a.AddRange(scanArgs);
            }
            else
            {
                // PATH'e guvenilmez: her zaman System32 altindaki Windows PowerShell
                exe = Path.Combine(Environment.SystemDirectory, @"WindowsPowerShell\v1.0\powershell.exe");
                a.Add("-NoProfile"); a.Add("-ExecutionPolicy"); a.Add("Bypass");
                a.Add("-File"); a.Add(Path.Combine(hostDir, "CortmedSecurity.ps1"));
                a.Add("-Mode"); a.Add("ScanFile"); a.Add("-Json");
            }
            a.Add("-Path"); a.Add(full);

            ProcessStartInfo psi = new ProcessStartInfo(exe, JoinArgs(a));
            psi.UseShellExecute = false;
            psi.CreateNoWindow = true;
            psi.WorkingDirectory = hostDir;
            psi.RedirectStandardInput = true;
            psi.RedirectStandardOutput = true;
            psi.RedirectStandardError = true;
            psi.StandardOutputEncoding = new UTF8Encoding(false);
            psi.StandardErrorEncoding = new UTF8Encoding(false);

            Process p;
            try { p = Process.Start(psi); }
            catch (Exception) { return Error(TitleNoStart); }
            if (p == null) return Error(TitleNoStart);

            using (p)
            {
                // Cocuk surec Chrome'un stdin/stdout borularina asla dokunmaz
                try { p.StandardInput.Close(); } catch (Exception) { }
                List<string> lines = new List<string>();
                object gate = new object();
                ManualResetEvent outDone = new ManualResetEvent(false);
                p.OutputDataReceived += delegate(object sender, DataReceivedEventArgs e)
                {
                    if (e.Data == null) { outDone.Set(); return; }
                    lock (gate)
                    {
                        lines.Add(e.Data);
                        if (lines.Count > MaxKeptLines) lines.RemoveAt(0);
                    }
                };
                p.ErrorDataReceived += delegate(object sender, DataReceivedEventArgs e) { };
                p.BeginOutputReadLine();
                p.BeginErrorReadLine();
                if (!p.WaitForExit(ScanTimeoutMs))
                {
                    try { p.Kill(); } catch (Exception) { }
                    try { p.WaitForExit(5000); } catch (Exception) { }
                    return Error(TitleTimeout);
                }
                // Ciktinin sonu (EOF) en fazla 5 sn beklenir; boruyu tutan bir torun surec kopruyu kilitlemesin
                outDone.WaitOne(5000);
                List<string> copy;
                lock (gate) copy = new List<string>(lines);
                return ParseScanOutput(copy);
            }
        }

        static Dictionary<string, object> ParseScanOutput(List<string> lines)
        {
            for (int i = lines.Count - 1; i >= 0; i--)
            {
                string l = (lines[i] ?? "").Trim().TrimStart('\uFEFF');
                if (l.Length == 0) continue;
                IDictionary<string, object> o = null;
                try { o = new JavaScriptSerializer().DeserializeObject(l) as IDictionary<string, object>; }
                catch (Exception) { o = null; }
                if (o == null || !o.ContainsKey("level")) continue;
                return Normalize(o);
            }
            return Error(TitleBadOutput);
        }

        static Dictionary<string, object> Normalize(IDictionary<string, object> o)
        {
            string level = o["level"] as string;
            if (level != "RED" && level != "YELLOW" && level != "OK") return Error(TitleScanFailed);
            object t;
            string title = o.TryGetValue("title", out t) ? t as string : null;
            List<object> reasons = new List<object>();
            object r;
            IList list = o.TryGetValue("reasons", out r) ? r as IList : null;
            if (list != null)
            {
                foreach (object item in list)
                {
                    string s = item as string;
                    if (s == null) continue;
                    reasons.Add(Cap(s));
                    if (reasons.Count >= MaxReasons) break;
                }
            }
            Dictionary<string, object> d = new Dictionary<string, object>();
            d["level"] = level;
            d["title"] = Cap(title ?? "");
            d["reasons"] = reasons.ToArray();
            return d;
        }

        static string Cap(string s)
        {
            if (s.Length <= MaxText) return s;
            int n = MaxText;
            if (char.IsHighSurrogate(s[n - 1])) n--;
            return s.Substring(0, n);
        }

        static Dictionary<string, object> Error(string title)
        {
            Dictionary<string, object> d = new Dictionary<string, object>();
            d["level"] = "ERROR";
            d["title"] = title;
            d["reasons"] = new object[0];
            return d;
        }

        static void WriteMessage(Stream output, Dictionary<string, object> msg)
        {
            string json = new JavaScriptSerializer().Serialize(msg);
            byte[] body = new UTF8Encoding(false).GetBytes(json);
            byte[] frame = new byte[4 + body.Length];
            int len = body.Length;
            frame[0] = (byte)(len & 0xFF);
            frame[1] = (byte)((len >> 8) & 0xFF);
            frame[2] = (byte)((len >> 16) & 0xFF);
            frame[3] = (byte)((len >> 24) & 0xFF);
            Buffer.BlockCopy(body, 0, frame, 4, body.Length);
            output.Write(frame, 0, frame.Length);
            output.Flush();
        }

        // CommandLineToArgvW kurallari; yollar zaten '"' icermez
        static string JoinArgs(List<string> args)
        {
            StringBuilder sb = new StringBuilder();
            foreach (string a in args)
            {
                if (sb.Length > 0) sb.Append(' ');
                sb.Append(Quote(a));
            }
            return sb.ToString();
        }

        static string Quote(string a)
        {
            if (a.Length > 0 && a.IndexOfAny(new char[] { ' ', '\t', '\n', '\v', '"' }) < 0) return a;
            StringBuilder sb = new StringBuilder("\"");
            int bs = 0;
            foreach (char c in a)
            {
                if (c == '\\') { bs++; continue; }
                if (c == '"') { sb.Append('\\', bs * 2 + 1); sb.Append('"'); bs = 0; continue; }
                sb.Append('\\', bs);
                bs = 0;
                sb.Append(c);
            }
            sb.Append('\\', bs * 2);
            sb.Append('"');
            return sb.ToString();
        }
    }
}
