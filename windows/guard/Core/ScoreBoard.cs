using System;
using System.Collections.Generic;

namespace Cortmed.Guard
{
    public enum DecisionLevel { Log, Warn, Freeze }

    public class Decision
    {
        public DecisionLevel Level;
        public int RootPid;
        public int Score;
        public List<string> Reasons = new List<string>();
    }

    /// <summary>
    /// Kok surec basina puan tutar. Ayni davranis pencerede bir kez sayilir.
    /// Thread-safe: tum genel metotlar tek bir kilit altinda calisir.
    /// CAGIRAN, Forget(root) METODUNU MUTLAKA CAGIRMALIDIR:
    /// (a) ProcessTree.OnProcessExit bir kok pid dondurdugunde, ve
    /// (b) yeni bir surec basladiginda ve kendi koku oldugunda (RootOf(pid) == pid);
    ///     boylece yeniden kullanilan bir kok pid eski Frozen bayragini/puanini devralmaz.
    /// Frozen olmayan ve son etkinligi WindowSeconds'tan eski durumlar otomatik atilir.
    /// </summary>
    public class ScoreBoard
    {
        class Entry
        {
            public Behavior Behavior;
            public DateTime Time;
            public string Reason;
        }

        class State
        {
            public bool BaseCounted;
            public int BaseScore;
            public bool Frozen;
            public DateTime LastActivity;
            public List<Entry> Hits = new List<Entry>();
            public Queue<DateTime> DocWrites = new Queue<DateTime>();
        }

        readonly BehaviorRules _rules;
        readonly Dictionary<int, State> _states = new Dictionary<int, State>();
        readonly object _lock = new object();

        public ScoreBoard(BehaviorRules r)
        {
            _rules = r;
        }

        public Decision Add(int rootPid, int baseScore, Hit hit, DateTime now)
        {
            lock (_lock)
            {
                EvictIdle(now);
                State s = GetState(rootPid, baseScore);
                s.LastActivity = now;
                Expire(s, now);
                if (hit != null) AddHit(s, hit.Behavior, hit.Reason, now);
                return Decide(rootPid, s);
            }
        }

        public Decision AddDocumentWrite(int rootPid, int baseScore, DateTime now)
        {
            lock (_lock)
            {
                EvictIdle(now);
                State s = GetState(rootPid, baseScore);
                s.LastActivity = now;
                Expire(s, now);
                s.DocWrites.Enqueue(now);
                while (s.DocWrites.Count > 0 && (now - s.DocWrites.Peek()).TotalSeconds > _rules.MassFileSeconds)
                    s.DocWrites.Dequeue();
                if (s.DocWrites.Count > _rules.MassFileCount)
                {
                    string reason;
                    _rules.Reasons.TryGetValue(Behavior.MassFileChange, out reason);
                    AddHit(s, Behavior.MassFileChange, reason, now);
                }
                return Decide(rootPid, s);
            }
        }

        public void Forget(int rootPid)
        {
            lock (_lock) { _states.Remove(rootPid); }
        }

        void EvictIdle(DateTime now)
        {
            List<int> dead = null;
            foreach (var kv in _states)
                if (!kv.Value.Frozen && (now - kv.Value.LastActivity).TotalSeconds > _rules.WindowSeconds)
                {
                    if (dead == null) dead = new List<int>();
                    dead.Add(kv.Key);
                }
            if (dead != null) foreach (int k in dead) _states.Remove(k);
        }

        State GetState(int rootPid, int baseScore)
        {
            State s;
            if (!_states.TryGetValue(rootPid, out s))
            {
                s = new State();
                _states[rootPid] = s;
            }
            if (!s.BaseCounted) { s.BaseCounted = true; s.BaseScore = baseScore; }
            return s;
        }

        void Expire(State s, DateTime now)
        {
            s.Hits.RemoveAll(h => (now - h.Time).TotalSeconds > _rules.WindowSeconds);
        }

        void AddHit(State s, Behavior b, string reason, DateTime now)
        {
            foreach (var h in s.Hits) if (h.Behavior == b) return;
            var e = new Entry();
            e.Behavior = b;
            e.Time = now;
            if (string.IsNullOrEmpty(reason)) _rules.Reasons.TryGetValue(b, out reason);
            e.Reason = reason ?? b.ToString();
            s.Hits.Add(e);
        }

        Decision Decide(int rootPid, State s)
        {
            var d = new Decision();
            d.RootPid = rootPid;
            int score = s.BaseScore;
            foreach (var h in s.Hits)
            {
                int pts;
                if (_rules.Points.TryGetValue(h.Behavior, out pts)) score += pts;
                d.Reasons.Add(h.Reason);
            }
            d.Score = score;
            if (score >= _rules.FreezeAt && !s.Frozen)
            {
                s.Frozen = true;
                d.Level = DecisionLevel.Freeze;
            }
            else if (score >= _rules.FreezeAt || score >= _rules.WarnAt) d.Level = DecisionLevel.Warn;
            else d.Level = DecisionLevel.Log;
            return d;
        }
    }
}
