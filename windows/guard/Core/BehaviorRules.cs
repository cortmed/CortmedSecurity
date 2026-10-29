using System;
using System.Collections;
using System.Collections.Generic;
using System.IO;
using System.Web.Script.Serialization;

namespace Cortmed.Guard
{
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
        public HashSet<string> NeverFreeze = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        public HashSet<string> TrustedImages = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

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

            var points = GetDict(root, "points");
            if (points != null)
                foreach (var kv in points) r.Points[ParseBehavior(kv.Key)] = ToInt(kv.Value, kv.Key);
            var reasons = GetDict(root, "reasons");
            if (reasons != null)
                foreach (var kv in reasons) r.Reasons[ParseBehavior(kv.Key)] = Convert.ToString(kv.Value);

            FillSet(root, "neverFreeze", r.NeverFreeze);
            FillSet(root, "trustedImages", r.TrustedImages);
            return r;
        }

        static Behavior ParseBehavior(string name)
        {
            Behavior b;
            if (!Enum.TryParse<Behavior>(name, false, out b) || !Enum.IsDefined(typeof(Behavior), b))
                throw new InvalidDataException("Bilinmeyen davranış adı: " + name);
            return b;
        }

        static Dictionary<string, object> GetDict(Dictionary<string, object> d, string key)
        {
            object v;
            if (!d.TryGetValue(key, out v) || v == null) return null;
            var res = v as Dictionary<string, object>;
            if (res == null) throw new InvalidDataException("'" + key + "' bir nesne olmalı.");
            return res;
        }

        static int GetInt(Dictionary<string, object> d, string key)
        {
            object v;
            if (!d.TryGetValue(key, out v) || v == null) return 0;
            return ToInt(v, key);
        }

        static int ToInt(object v, string key)
        {
            try { return Convert.ToInt32(v); }
            catch (Exception) { throw new InvalidDataException("'" + key + "' sayı olmalı."); }
        }

        static void FillSet(Dictionary<string, object> d, string key, HashSet<string> set)
        {
            object v;
            if (!d.TryGetValue(key, out v) || v == null) return;
            var list = v as IEnumerable;
            if (list == null || v is string) throw new InvalidDataException("'" + key + "' bir liste olmalı.");
            foreach (object o in list) set.Add(Convert.ToString(o));
        }
    }
}
