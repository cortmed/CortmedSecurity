using System;
using System.Collections.Generic;
using System.IO;

namespace Cortmed.Guard
{
    // Calisan sureclerin ebeveyn agaci.
    // Kok kurali: ebeveyni bilinmeyen ya da ebeveyni explorer.exe/services.exe olan
    // surec kendi kokudur; diger sureclerin koku ebeveyninin kokudur.
    // Tasarim: kok, surec BASLARKEN hesaplanip kaydedilir. Cikan bir surec, hayattaki
    // torunu kaldigi surece kayitta tutulur (RootOf/ImageOf bozulmasin); torunu kalmayinca silinir.
    public class ProcessTree
    {
        class Node
        {
            public int Pid;
            public int Parent;
            public string Image;
            public int Root;
            public bool Alive;
            public int Kids; // kayitta tutulan dogrudan cocuk sayisi
        }

        readonly Dictionary<int, Node> _nodes = new Dictionary<int, Node>();
        readonly object _lock = new object();

        static bool IsShell(string image)
        {
            string n = FileName(image);
            return n.Equals("explorer.exe", StringComparison.OrdinalIgnoreCase)
                || n.Equals("services.exe", StringComparison.OrdinalIgnoreCase);
        }

        static string FileName(string path)
        {
            if (string.IsNullOrEmpty(path)) return "";
            int i = path.LastIndexOfAny(new[] { '\\', '/' });
            return i >= 0 ? path.Substring(i + 1) : path;
        }

        public void OnProcessStart(GuardEvent e)
        {
            if (e == null) return;
            lock (_lock)
            {
                Node old;
                int kids = 0;
                if (_nodes.TryGetValue(e.Pid, out old))
                {
                    // pid yeniden kullanildi: eski kaydi birak, cocuk sayisini koru
                    kids = old.Kids;
                    Node oldParent;
                    if (_nodes.TryGetValue(old.Parent, out oldParent) && oldParent.Kids > 0) oldParent.Kids--;
                }

                var n = new Node();
                n.Pid = e.Pid;
                n.Parent = e.ParentPid;
                n.Image = e.Image ?? "";
                n.Alive = true;
                n.Kids = kids;

                Node p;
                if (e.ParentPid != e.Pid && _nodes.TryGetValue(e.ParentPid, out p))
                {
                    p.Kids++;
                    n.Root = IsShell(p.Image) ? e.Pid : p.Root;
                }
                else
                {
                    n.Root = e.Pid;
                }
                _nodes[e.Pid] = n;
            }
        }

        public void OnProcessExit(int pid)
        {
            lock (_lock)
            {
                Node n;
                if (!_nodes.TryGetValue(pid, out n)) return;
                n.Alive = false;
                Prune(n);
            }
        }

        // Olu ve cocugu kalmayan kayitlari yukari dogru siler.
        void Prune(Node n)
        {
            while (n != null && !n.Alive && n.Kids <= 0)
            {
                _nodes.Remove(n.Pid);
                Node p;
                if (n.Parent != n.Pid && _nodes.TryGetValue(n.Parent, out p))
                {
                    if (p.Kids > 0) p.Kids--;
                    n = p;
                }
                else n = null;
            }
        }

        public int RootOf(int pid)
        {
            lock (_lock)
            {
                Node n;
                return _nodes.TryGetValue(pid, out n) ? n.Root : pid;
            }
        }

        // Koku ve hayattaki tum torunlari.
        public List<int> Subtree(int rootPid)
        {
            var res = new List<int>();
            lock (_lock)
            {
                foreach (var n in _nodes.Values)
                    if (n.Alive && n.Root == rootPid) res.Add(n.Pid);
            }
            res.Sort();
            return res;
        }

        public string ImageOf(int pid)
        {
            lock (_lock)
            {
                Node n;
                return _nodes.TryGetValue(pid, out n) ? n.Image : "";
            }
        }
    }
}
