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

    // Kok surec basina puan tutar. Ayni davranis pencerede bir kez sayilir.
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
                State s = GetState(rootPid, baseScore);
                Expire(s, now);
                if (hit != null) AddHit(s, hit.Behavior, hit.Reason, now);
                return Decide(rootPid, s);
            }
        }

        public Decision AddDocumentWrite(int rootPid, int baseScore, DateTime now)
        {
            lock (_lock)
            {
                State s = GetState(rootPid, baseScore);
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
