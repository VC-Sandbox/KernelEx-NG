// hello.cs - .NET 4 console test for KernelEx-NG: runtime version, OS, a little of everything, result to C:\NETHELLO.TXT
using System;
using System.IO;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
class Hello {
    static int Main() {
        var w = new StringWriter();
        w.WriteLine("CLR " + Environment.Version + "  OS " + Environment.OSVersion + "  64-bit " + Environment.Is64BitProcess);
        w.WriteLine("LINQ sum " + Enumerable.Range(1, 100).Sum());
        var t = Task.Factory.StartNew(() => Thread.CurrentThread.ManagedThreadId);
        w.WriteLine("Task thread " + t.Result);
        w.WriteLine("Parallel " + Enumerable.Range(1, 1000).AsParallel().Select(x => x * 2).Sum());
        w.WriteLine("Now " + DateTime.Now.ToString("u") + "  culture " + System.Globalization.CultureInfo.CurrentCulture.Name);
        try { w.WriteLine("Regex " + System.Text.RegularExpressions.Regex.Replace("KernelEx 98", @"\d+", "NG")); } catch (Exception e) { w.WriteLine("Regex FAILED " + e.GetType()); }
        try { using (var c = new System.Net.WebClient()) w.WriteLine("Http " + c.DownloadString("http://10.0.2.2:8000/").Length); } catch (Exception e) { w.WriteLine("Http " + e.ToString()); for (var i = e.InnerException; i != null; i = i.InnerException) w.WriteLine("  inner: " + i.ToString()); }
        File.WriteAllText(@"C:\NETHELLO.TXT", w.ToString());
        return 0;
    }
}
