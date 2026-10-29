// Cortmed Security baslaticisi: CortmedSecurity.ps1'i kendi surecinde calistiran kucuk bir Windows programi.
// Boylece gorev cubugu, Gorev Yoneticisi ve sistem tepsisinde "Cortmed Security" adi ve logosu gorunur,
// acilista konsol penceresi yanip sonmez. Install.ps1 bunu kurulumda Windows'un C# derleyicisiyle derler.
//
// Kullanim:  CortmedSecurity.exe            panel
//            CortmedSecurity.exe --watch    arka plan bekcisi (sistem tepsisi)
//            CortmedSecurity.exe --scan     tam tarama
//            CortmedSecurity.exe --mode X   CortmedSecurity.ps1 -Mode X
using System;
using System.IO;
using System.Management.Automation;
using System.Management.Automation.Runspaces;
using System.Reflection;
using System.Threading;
using System.Windows.Forms;

[assembly: AssemblyTitle("Cortmed Security")]
[assembly: AssemblyDescription("Cortmed Security")]
[assembly: AssemblyProduct("Cortmed Security")]
[assembly: AssemblyCompany("Cortmed")]
[assembly: AssemblyVersion("1.0.0.0")]
[assembly: AssemblyFileVersion("1.0.0.0")]

static class Program
{
    [STAThread]
    static int Main(string[] args)
    {
        string mode = "Panel";
        string path = null;
        for (int i = 0; i < args.Length; i++)
        {
            string a = args[i].ToLowerInvariant();
            if (a == "--watch") mode = "Watch";
            else if (a == "--scan") mode = "Daily";
            else if (a == "--mode" && i + 1 < args.Length) mode = args[++i];
            else if (a == "--file" && i + 1 < args.Length) { mode = "ScanFile"; path = args[++i]; }
        }

        string dir = AppDomain.CurrentDomain.BaseDirectory;
        string script = Path.Combine(dir, "CortmedSecurity.ps1");
        try
        {
            InitialSessionState iss = InitialSessionState.CreateDefault();
            iss.ExecutionPolicy = Microsoft.PowerShell.ExecutionPolicy.Bypass;
            using (Runspace rs = RunspaceFactory.CreateRunspace(iss))
            {
                // Pencereler ve dosya secme kutusu icin STA ve ayni is parcacigi gerekir
                rs.ApartmentState = ApartmentState.STA;
                rs.ThreadOptions = PSThreadOptions.UseCurrentThread;
                rs.Open();
                using (PowerShell ps = PowerShell.Create())
                {
                    ps.Runspace = rs;
                    ps.AddCommand(script).AddParameter("Mode", mode);
                    if (path != null) ps.AddParameter("Path", path);
                    ps.Invoke();
                    if (ps.HadErrors)
                    {
                        foreach (ErrorRecord e in ps.Streams.Error) Log(dir, e.ToString() + " @ " + e.InvocationInfo.PositionMessage);
                    }
                }
            }
        }
        catch (Exception ex)
        {
            Log(dir, ex.ToString());
            if (mode == "Panel")
                MessageBox.Show("Cortmed Security açılamadı:\n\n" + ex.Message, "Cortmed Security",
                    MessageBoxButtons.OK, MessageBoxIcon.Error);
            return 1;
        }
        return 0;
    }

    static void Log(string dir, string text)
    {
        try
        {
            string data = Path.Combine(dir, "data");
            Directory.CreateDirectory(data);
            File.AppendAllText(Path.Combine(data, "launcher-errors.txt"),
                DateTime.Now.ToString("yyyy-MM-dd HH:mm:ss") + "  " + text + Environment.NewLine);
        }
        catch { }
    }
}
