// Cortmed Engine - Windows tarafi parmak izi veritabani okuyucu (CMDB v1).
// PowerShell 5.1 Add-Type ile derlenir; bu yuzden C# 5 sozdizimi kullanilir.
using System;
using System.IO;
using System.Runtime.InteropServices;
using System.Runtime.InteropServices.ComTypes;
using System.Security.Cryptography;
using System.Text;

namespace Cortmed
{
    public class CortmedDb
    {
        public long BuildTime;
        private string[] families;
        private ulong[] sha;
        private ushort[] shaFamily;
        private ulong[] md5;

        public int SignatureCount { get { return sha.Length + md5.Length; } }

        public static CortmedDb Load(string path)
        {
            byte[] b = File.ReadAllBytes(path);
            int pos = 0;
            if (Encoding.ASCII.GetString(b, 0, 4) != "CMDB") throw new InvalidDataException("Gecersiz CMDB dosyasi");
            pos = 4;
            int version = BitConverter.ToUInt16(b, pos); pos += 4;
            if (version != 1) throw new InvalidDataException("Desteklenmeyen CMDB surumu " + version);
            CortmedDb db = new CortmedDb();
            db.BuildTime = BitConverter.ToInt64(b, pos); pos += 8;
            int nFam = BitConverter.ToInt32(b, pos); pos += 4;
            db.families = new string[nFam];
            for (int i = 0; i < nFam; i++)
            {
                int len = BitConverter.ToUInt16(b, pos); pos += 2;
                db.families[i] = Encoding.UTF8.GetString(b, pos, len); pos += len;
            }
            int nSha = BitConverter.ToInt32(b, pos); pos += 4;
            db.sha = new ulong[nSha];
            Buffer.BlockCopy(b, pos, db.sha, 0, nSha * 8); pos += nSha * 8;
            db.shaFamily = new ushort[nSha];
            Buffer.BlockCopy(b, pos, db.shaFamily, 0, nSha * 2); pos += nSha * 2;
            int nMd5 = BitConverter.ToInt32(b, pos); pos += 4;
            db.md5 = new ulong[nMd5];
            Buffer.BlockCopy(b, pos, db.md5, 0, nMd5 * 8);
            return db;
        }

        private static ulong Prefix(byte[] h)
        {
            ulong v = 0;
            for (int i = 0; i < 8; i++) v = (v << 8) | h[i];
            return v;
        }

        /// Eslesme varsa aile adi ("" = bilinmeyen aile), yoksa null.
        public string Lookup(byte[] sha256, byte[] md5Hash)
        {
            int i = Array.BinarySearch(sha, Prefix(sha256));
            if (i >= 0)
            {
                int fam = shaFamily[i];
                return (fam >= 1 && fam <= families.Length) ? families[fam - 1] : "";
            }
            if (Array.BinarySearch(md5, Prefix(md5Hash)) >= 0) return "";
            return null;
        }

        public string LookupHex(string sha256Hex, string md5Hex)
        {
            return Lookup(FromHex(sha256Hex), FromHex(md5Hex));
        }

        /// Dosyanin [SHA-256, MD5] parmak izleri (kucuk harf hex). Kilitli dosyalari da okumaya calisir.
        public static string[] HashFile(string path)
        {
            using (FileStream fs = new FileStream(path, FileMode.Open, FileAccess.Read,
                FileShare.ReadWrite | FileShare.Delete, 1 << 16))
            using (SHA256 s = SHA256.Create())
            using (MD5 m = MD5.Create())
            {
                byte[] buf = new byte[1 << 16];
                int n;
                while ((n = fs.Read(buf, 0, buf.Length)) > 0)
                {
                    s.TransformBlock(buf, 0, n, null, 0);
                    m.TransformBlock(buf, 0, n, null, 0);
                }
                s.TransformFinalBlock(buf, 0, 0);
                m.TransformFinalBlock(buf, 0, 0);
                return new string[] { ToHex(s.Hash), ToHex(m.Hash) };
            }
        }

        /// Dosyanin ilk maxBytes baytinin Shannon entropisi (0-8). 7.4 ustu genelde sikistirilmis/gizlenmis icerik.
        public static double Entropy(string path, int maxBytes)
        {
            long[] counts = new long[256];
            long total = 0;
            using (FileStream fs = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete))
            {
                byte[] buf = new byte[1 << 16];
                int n;
                while (total < maxBytes && (n = fs.Read(buf, 0, buf.Length)) > 0)
                {
                    for (int i = 0; i < n; i++) counts[buf[i]]++;
                    total += n;
                }
            }
            if (total == 0) return 0;
            double e = 0;
            foreach (long c in counts)
            {
                if (c == 0) continue;
                double p = (double)c / total;
                e -= p * Math.Log(p, 2);
            }
            return e;
        }

        private static string ToHex(byte[] b)
        {
            StringBuilder sb = new StringBuilder(b.Length * 2);
            foreach (byte x in b) sb.Append(x.ToString("x2"));
            return sb.ToString();
        }

        private static byte[] FromHex(string s)
        {
            byte[] r = new byte[s.Length / 2];
            for (int i = 0; i < r.Length; i++) r[i] = Convert.ToByte(s.Substring(i * 2, 2), 16);
            return r;
        }
    }

    /// Windows'un uygulamayi "PowerShell" degil "Cortmed Security" olarak tanimasi icin:
    /// gorev cubugu simgesi, sabitleme ve bildirimlerde Cortmed adi ve logosu gorunur.
    public static class AppIdentity
    {
        public const string Id = "Cortmed.Security";

        [DllImport("shell32.dll", CharSet = CharSet.Unicode)]
        private static extern int SetCurrentProcessExplicitAppUserModelID(string appId);

        public static void ApplyToProcess()
        {
            SetCurrentProcessExplicitAppUserModelID(Id);
        }

        [ComImport, Guid("00021401-0000-0000-C000-000000000046")]
        private class CShellLink { }

        [ComImport, InterfaceType(ComInterfaceType.InterfaceIsIUnknown), Guid("886D8EEB-8CF2-4446-8D02-CDBA1DBDCF99")]
        private interface IPropertyStore
        {
            void GetCount(out uint count);
            void GetAt(uint index, out PropertyKey key);
            void GetValue(ref PropertyKey key, out PropVariant value);
            void SetValue(ref PropertyKey key, ref PropVariant value);
            void Commit();
        }

        [StructLayout(LayoutKind.Sequential, Pack = 4)]
        private struct PropertyKey
        {
            public Guid fmtid;
            public uint pid;
        }

        [StructLayout(LayoutKind.Explicit, Size = 16)]
        private struct PropVariant
        {
            [FieldOffset(0)] public ushort vt;
            [FieldOffset(8)] public IntPtr pointer;
        }

        /// Kisayola uygulama kimligini yazar (bildirimlerin Cortmed adiyla gelmesi icin gerekli).
        public static void SetShortcutAppId(string lnkPath)
        {
            object link = new CShellLink();
            IPersistFile file = (IPersistFile)link;
            file.Load(lnkPath, 2);
            IPropertyStore store = (IPropertyStore)link;
            PropertyKey key = new PropertyKey();
            key.fmtid = new Guid("9F4C2855-9F79-4B39-A8D0-E1D42DE1D5F3");
            key.pid = 5;
            PropVariant value = new PropVariant();
            value.vt = 31; // VT_LPWSTR
            value.pointer = Marshal.StringToCoTaskMemUni(Id);
            try
            {
                store.SetValue(ref key, ref value);
                store.Commit();
                file.Save(lnkPath, true);
            }
            finally
            {
                Marshal.FreeCoTaskMem(value.pointer);
                Marshal.ReleaseComObject(link);
            }
        }
    }

    /// Gece isinin imzasini dogrular: ECDSA P-256 + SHA-256, imza DER bicimde (engine/sign_db.py).
    public static class Signing
    {
        public static bool Verify(byte[] data, byte[] derSignature, string publicXHex, string publicYHex)
        {
            try
            {
                ECPoint q = new ECPoint();
                q.X = FromHex(publicXHex);
                q.Y = FromHex(publicYHex);
                ECParameters p = new ECParameters();
                p.Curve = ECCurve.NamedCurves.nistP256;
                p.Q = q;
                using (ECDsa ecdsa = ECDsa.Create(p))
                {
                    return ecdsa.VerifyData(data, DerToP1363(derSignature), HashAlgorithmName.SHA256);
                }
            }
            catch { return false; }
        }

        // DER: 30 len 02 rlen r 02 slen s  ->  r||s (her biri 32 bayt)
        private static byte[] DerToP1363(byte[] der)
        {
            int pos = 2;
            if ((der[1] & 0x80) != 0) pos += der[1] & 0x7F;
            byte[] r = ReadInt(der, ref pos);
            byte[] s = ReadInt(der, ref pos);
            byte[] raw = new byte[64];
            Buffer.BlockCopy(r, 0, raw, 32 - r.Length, r.Length);
            Buffer.BlockCopy(s, 0, raw, 64 - s.Length, s.Length);
            return raw;
        }

        private static byte[] ReadInt(byte[] der, ref int pos)
        {
            if (der[pos] != 0x02) throw new InvalidDataException("DER imza bozuk");
            int len = der[pos + 1];
            int start = pos + 2;
            pos = start + len;
            while (len > 32 && der[start] == 0) { start++; len--; }
            if (len > 32) throw new InvalidDataException("DER imza bozuk");
            byte[] v = new byte[len];
            Buffer.BlockCopy(der, start, v, 0, len);
            return v;
        }

        private static byte[] FromHex(string s)
        {
            byte[] r = new byte[s.Length / 2];
            for (int i = 0; i < r.Length; i++) r[i] = Convert.ToByte(s.Substring(i * 2, 2), 16);
            return r;
        }
    }
}
