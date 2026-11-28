// T.cs - shared test logger for the .NET stress tests: one PASS/FAIL line per check, flushed at once, so a crash or
// hang leaves the last line that ran. Log: C:\T\<name>.LOG
using System;
using System.IO;
using System.Threading;

public delegate void Fn();

public static class T {
    static StreamWriter w; static int pass, fail;
    public static void Init(string name) {
        w = new StreamWriter(@"C:\T\" + name + ".LOG", false); w.AutoFlush = true;
        AppDomain.CurrentDomain.UnhandledException += delegate(object o, UnhandledExceptionEventArgs e) {
            lock (w) w.WriteLine("UNHANDLED (terminating " + e.IsTerminating + "): " + e.ExceptionObject); };
        w.WriteLine("START " + name + " " + Environment.Version + " " + Environment.OSVersion + " " + DateTime.Now);
    }
    public static void Log(string s) { lock (w) w.WriteLine("  " + s); }
    public static void Run(string n, Fn f) {
        DateTime t0 = DateTime.Now;
        lock (w) w.WriteLine("RUN  " + n);
        try { f(); pass++; lock (w) w.WriteLine("PASS " + n + " (" + (int)(DateTime.Now - t0).TotalMilliseconds + " ms)"); }
        catch (Exception e) { fail++; lock (w) w.WriteLine("FAIL " + n + ": " + e.ToString()); }
    }
    public static void Check(bool c, string what) { if (!c) throw new Exception("check failed: " + what); }
    public static int End() { w.WriteLine("END pass " + pass + " fail " + fail); w.Close(); return fail; }
}
