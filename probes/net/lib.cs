// lib.cs - LIB.DLL: run through ICLRRuntimeHost::ExecuteInDefaultAppDomain (no EXE assembly involved)
using System; using System.Linq;
public class Entry { public static int Run(string arg) {
    string s = "hosted: CLR " + Environment.Version + " OS " + Environment.OSVersion + " LINQ " + Enumerable.Range(1, 10).Sum() + " arg " + arg;
    try { s += " Regex " + System.Text.RegularExpressions.Regex.Replace("a1b22", @"\d+", "#"); } catch (Exception e) { s += " Regex FAIL " + e.GetType().Name; }
    System.IO.File.WriteAllText(@"C:\NETLIB.TXT", s); return 42; } }
