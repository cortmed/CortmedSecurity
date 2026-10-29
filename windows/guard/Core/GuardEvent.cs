using System;

namespace Cortmed.Guard
{
    public enum Behavior
    {
        Persistence,
        TamperOtherApp,
        HiddenScript,
        DisableProtection,
        Injection,
        LsassAccess,
        MassFileChange
    }

    public class GuardEvent
    {
        public int EventId;
        public DateTime Time;
        public int Pid;
        public int ParentPid;
        public string Image;
        public string ParentImage;
        public string CommandLine;
        public string TargetObject;
        public string TargetFilename;
        public int TargetPid;
        public string TargetImage;
        public string Hashes;
    }

    // Pid: puanin yazilacagi surec (cogunlukla olayi yapan, bazen ebeveyn).
    public class Hit
    {
        public Behavior Behavior;
        public int Pid;
        public string Reason;
    }
}
