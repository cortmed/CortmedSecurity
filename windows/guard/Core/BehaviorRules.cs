using System;
using System.Collections;
using System.Collections.Generic;
using System.IO;
using System.Web.Script.Serialization;

namespace Cortmed.Guard
{
    // Imzali davranis kurallari. Parse eksik ya da aralik disi her degerde InvalidDataException
    // firlatir; hizmet bu durumda son gecerli kopyaya (.good) doner. Ayni denetimler
    // engine/sign_db.py'de imzalamadan once yapilir.
    public class BehaviorRules
    {
        public int FreezeAt;
        public int WarnAt;
        public int WindowSeconds;
        public int MassFileCount;
        public int MassFileSeconds;
        public int TrustedLocationBonus;
        public Dictionary<Behavior, int> Points = new Dictionary<Behavior, int>();
        public Dictionary<Behavior, string> Reasons = new Dictionary<Behavior, string>();
        // Tam yol kaliplari (PathRules); ProcessControl'deki sabit taban listesine eklenir, onu daraltamaz.
        public HashSet<string> NeverFreeze = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        // LSASS'a erisebilen tam yol kaliplari.
        public HashSet<string> TrustedImages = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        // Cocuklari kendi agacini baslatan programlar: dosya adi ("msedge.exe") ya da yol sonu ("\Discord\Update.exe").
        public HashSet<string> Launchers = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

        public const int MinPoints = -100, MaxPoints = 200;

        public static BehaviorRules Parse(string json)
        {
            object parsed;
            try { parsed = new JavaScriptSerializer().DeserializeObject(json); }
            catch (Exception ex) { throw new InvalidDataException("Kural dosyası okunamadı: " + ex.Message, ex); }
            var root = parsed as Dictionary<string, object>;
            if (root == null) throw new InvalidDataException("Kural dosyası bir nesne olmalı.");

            var r = new BehaviorRules();
            r.FreezeAt = GetInt(root, "freezeAt");
            r.WarnAt = GetInt(root, "warnAt");
            r.WindowSeconds = GetInt(root, "windowSeconds");
            r.MassFileCount = GetInt(root, "massFileCount");
            r.MassFileSeconds = GetInt(root, "massFileSeconds");
            r.TrustedLocationBonus = GetInt(root, "trustedLocationBonus");

            foreach (var kv in GetDict(root, "points")) r.Points[ParseBehavior(kv.Key)] = ToInt(kv.Value, kv.Key);
            foreach (var kv in GetDict(root, "reasons"))
            {
                var s = kv.Value as string;
                if (string.IsNullOrEmpty(s)) throw new InvalidDataException("'reasons." + kv.Key + "' boş olamaz.");
                r.Reasons[ParseBehavior(kv.Key)] = s;
            }

            FillPaths(root, "neverFreeze", r.NeverFreeze);
            FillPaths(root, "trustedImages", r.TrustedImages);
            FillNames(root, "launchers", r.Launchers);
            Validate(r);
            return r;
        }

        static void Validate(BehaviorRules r)
        {
            Range("freezeAt", r.FreezeAt, 50, 200);
            Range("warnAt", r.WarnAt, 20, r.FreezeAt - 1);
            Range("windowSeconds", r.WindowSeconds, 30, 3600);
            Range("massFileCount", r.MassFileCount, 10, 1000);
            Range("massFileSeconds", r.MassFileSeconds, 1, 120);
            Range("trustedLocationBonus", r.TrustedLocationBonus, MinPoints, MaxPoints);
            foreach (Behavior b in Enum.GetValues(typeof(Behavior)))
            {
                int p;
                if (!r.Points.TryGetValue(b, out p)) throw new InvalidDataException("'points." + b + "' eksik.");
                Range("points." + b, p, MinPoints, MaxPoints);
                if (!r.Reasons.ContainsKey(b)) throw new InvalidDataException("'reasons." + b + "' eksik.");
            }
        }

        static void Range(string key, int v, int min, int max)
        {
            if (v < min || v > max)
                throw new InvalidDataException("'" + key + "' " + min + ".." + max + " aralığında olmalı (" + v + ").");
        }

        static Behavior ParseBehavior(string name)
        {
            Behavior b;
            if (!Enum.TryParse<Behavior>(name, false, out b) || !Enum.IsDefined(typeof(Behavior), b))
                throw new InvalidDataException("Bilinmeyen davranış adı: " + name);
            return b;
        }

        static object Require(Dictionary<string, object> d, string key)
        {
            object v;
            if (!d.TryGetValue(key, out v) || v == null) throw new InvalidDataException("'" + key + "' eksik.");
            return v;
        }

        static Dictionary<string, object> GetDict(Dictionary<string, object> d, string key)
        {
            var res = Require(d, key) as Dictionary<string, object>;
            if (res == null) throw new InvalidDataException("'" + key + "' bir nesne olmalı.");
            return res;
        }

        static int GetInt(Dictionary<string, object> d, string key)
        {
            return ToInt(Require(d, key), key);
        }

        static int ToInt(object v, string key)
        {
            if (!(v is int || v is long || v is decimal || v is double))
                throw new InvalidDataException("'" + key + "' sayı olmalı.");
            try
            {
                decimal m = Convert.ToDecimal(v);
                if (m != decimal.Truncate(m)) throw new InvalidDataException("'" + key + "' tam sayı olmalı.");
                return Convert.ToInt32(m);
            }
            catch (InvalidDataException) { throw; }
            catch (Exception) { throw new InvalidDataException("'" + key + "' sayı olmalı."); }
        }

        internal static List<string> GetList(Dictionary<string, object> d, string key)
        {
            object v = Require(d, key);
            var list = v as IEnumerable;
            if (list == null || v is string || v is Dictionary<string, object>) throw new InvalidDataException("'" + key + "' bir liste olmalı.");
            var res = new List<string>();
            foreach (object o in list)
            {
                var s = o as string;
                if (string.IsNullOrEmpty(s)) throw new InvalidDataException("'" + key + "' yalnızca dolu metin içermeli.");
                res.Add(s);
            }
            return res;
        }

        // "ad.exe" (klasorsuz) ya da "\klasor\ad.exe" (yol sonu).
        static void FillNames(Dictionary<string, object> d, string key, HashSet<string> set)
        {
            foreach (string s in GetList(d, key))
            {
                bool ok = s.EndsWith(".exe", StringComparison.OrdinalIgnoreCase) && s.Length > 4 && s.IndexOf('/') < 0 && s.IndexOf(':') < 0
                    && (s.IndexOf('\\') < 0 || (s[0] == '\\' && s.IndexOf("\\\\", StringComparison.Ordinal) < 0 && s.LastIndexOf('\\') < s.Length - 5));
                if (!ok) throw new InvalidDataException("'" + key + "' dosya adı (ad.exe) ya da yol sonu (\\klasör\\ad.exe) olmalı: " + s);
                set.Add(s);
            }
        }

        static void FillPaths(Dictionary<string, object> d, string key, HashSet<string> set)
        {
            foreach (string s in GetList(d, key))
            {
                if (!PathRules.IsValidPattern(s))
                    throw new InvalidDataException("'" + key + "' tam yol olmalı ({System32}\\... gibi): " + s);
                set.Add(s);
            }
        }
    }
}
