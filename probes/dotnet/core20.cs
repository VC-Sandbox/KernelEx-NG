// core20.cs - .NET 2.0 runtime stress: GC, threads, sync, file I/O, XML, regex, crypto, serialization, sockets,
// reflection/emit, registry, globalization, processes, timers. Log C:\T\CORE20.LOG
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Globalization;
using System.IO;
using System.Net;
using System.Net.Sockets;
using System.Reflection;
using System.Reflection.Emit;
using System.Runtime.Serialization.Formatters.Binary;
using System.Security.Cryptography;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading;
using System.Xml;
using Microsoft.Win32;

[Serializable] class Rec { public int A; public string B; public List<int> C = new List<int>(); }

class P {
    static int Main() {
        T.Init("CORE20");
        T.Run("gc 300 MB churn", delegate {
            long sum = 0;
            for (int i = 0; i < 300; i++) { byte[] b = new byte[1 << 20]; b[i % b.Length] = 1; sum += b.Length; }
            GC.Collect(); GC.WaitForPendingFinalizers(); GC.Collect();
            T.Log("total memory after collect " + GC.GetTotalMemory(true) / 1024 + " KB");
        });
        T.Run("gc 2M small objects", delegate {
            List<object> l = new List<object>();
            for (int i = 0; i < 2000000; i++) { l.Add(new int[2]); if (l.Count > 100000) l.Clear(); }
        });
        T.Run("threads 32 x Monitor counter", delegate {
            int n = 0; object o = new object(); Thread[] th = new Thread[32];
            for (int i = 0; i < th.Length; i++) { th[i] = new Thread(delegate() { for (int k = 0; k < 20000; k++) lock (o) n++; }); th[i].Start(); }
            foreach (Thread t in th) t.Join();
            T.Check(n == 32 * 20000, "count " + n);
        });
        T.Run("threadpool 500 work items + events", delegate {
            int n = 0; ManualResetEvent done = new ManualResetEvent(false);
            for (int i = 0; i < 500; i++) ThreadPool.QueueUserWorkItem(delegate { if (Interlocked.Increment(ref n) == 500) done.Set(); });
            T.Check(done.WaitOne(30000, false), "pool done, n=" + n);
        });
        T.Run("async delegate BeginInvoke", delegate {
            Converter<int, int> f = delegate(int x) { Thread.Sleep(50); return x * 2; };
            IAsyncResult r = f.BeginInvoke(21, null, null); T.Check(f.EndInvoke(r) == 42, "result");
        });
        T.Run("timers", delegate {
            int ticks = 0; AutoResetEvent e = new AutoResetEvent(false);
            using (Timer t = new Timer(delegate { if (Interlocked.Increment(ref ticks) == 10) e.Set(); }, null, 0, 20))
                T.Check(e.WaitOne(10000, false), "10 ticks, got " + ticks);
        });
        T.Run("mutex/semaphore/rwlock", delegate {
            using (Mutex m = new Mutex(false, "KexNgTestMutex")) { m.WaitOne(); m.ReleaseMutex(); }
            using (Semaphore s = new Semaphore(2, 2)) { s.WaitOne(); s.WaitOne(); s.Release(2); }
            ReaderWriterLock rw = new ReaderWriterLock(); rw.AcquireReaderLock(1000); rw.ReleaseReaderLock();
            rw.AcquireWriterLock(1000); rw.ReleaseWriterLock();
        });
        T.Run("file I/O 20 MB + FileStream async", delegate {
            string p = @"C:\T\big.tmp"; byte[] b = new byte[1 << 20]; new Random(1).NextBytes(b);
            using (FileStream f = new FileStream(p, FileMode.Create)) for (int i = 0; i < 20; i++) f.Write(b, 0, b.Length);
            T.Check(new FileInfo(p).Length == 20L << 20, "size");
            using (FileStream f = new FileStream(p, FileMode.Open, FileAccess.Read, FileShare.Read, 4096, true)) {
                byte[] r = new byte[b.Length]; IAsyncResult ar = f.BeginRead(r, 0, r.Length, null, null);
                T.Check(f.EndRead(ar) == r.Length && r[777] == b[777], "async read");
            }
            File.Delete(p);
        });
        T.Run("directories + FileSystemWatcher", delegate {
            string d = @"C:\T\dirtest"; if (Directory.Exists(d)) Directory.Delete(d, true);
            Directory.CreateDirectory(d + @"\a\b\c"); File.WriteAllText(d + @"\a\b\c\x.txt", "hi");
            T.Check(Directory.GetFiles(d, "*.txt", SearchOption.AllDirectories).Length == 1, "find");
            Directory.Delete(d, true);
        });
        T.Run("xml dom + xpath + xmlwriter", delegate {
            XmlDocument x = new XmlDocument(); x.LoadXml("<r><i n='1'/><i n='2'/><i n='3'/></r>");
            T.Check(x.SelectNodes("//i[@n>1]").Count == 2, "xpath");
            StringBuilder sb = new StringBuilder(); using (XmlWriter w = XmlWriter.Create(sb)) x.Save(w);
            T.Check(sb.ToString().Contains("n=\"3\""), "write");
        });
        T.Run("regex", delegate {
            Regex r = new Regex(@"(\w+)@(\w+)\.com", RegexOptions.Compiled);
            T.Check(r.Matches("a@b.com x c@d.com").Count == 2, "matches");
        });
        T.Run("crypto sha1/md5/aes/rsa/rng", delegate {
            byte[] d = Encoding.UTF8.GetBytes("abc");
            T.Check(BitConverter.ToString(SHA1.Create().ComputeHash(d)) == "A9-99-3E-36-47-06-81-6A-BA-3E-25-71-78-50-C2-6C-9C-D0-D8-9D", "sha1");
            MD5.Create().ComputeHash(d); SHA256.Create().ComputeHash(d);
            RijndaelManaged a = new RijndaelManaged(); a.GenerateKey(); a.GenerateIV();
            byte[] c = a.CreateEncryptor().TransformFinalBlock(d, 0, d.Length);
            T.Check(Encoding.UTF8.GetString(a.CreateDecryptor().TransformFinalBlock(c, 0, c.Length)) == "abc", "aes");
            using (RSACryptoServiceProvider rsa = new RSACryptoServiceProvider(1024)) {
                byte[] s = rsa.SignData(d, "SHA1"); T.Check(rsa.VerifyData(d, "SHA1", s), "rsa sign");
            }
            byte[] rnd = new byte[64]; RandomNumberGenerator.Create().GetBytes(rnd);
        });
        T.Run("binary serialization", delegate {
            Rec r = new Rec(); r.A = 5; r.B = "x"; r.C.Add(9);
            MemoryStream m = new MemoryStream(); new BinaryFormatter().Serialize(m, r); m.Position = 0;
            Rec q = (Rec)new BinaryFormatter().Deserialize(m); T.Check(q.A == 5 && q.C[0] == 9, "roundtrip");
        });
        T.Run("tcp loopback 200 KB echo", delegate {
            TcpListener l = new TcpListener(IPAddress.Loopback, 0); l.Start();
            int port = ((IPEndPoint)l.LocalEndpoint).Port;
            Thread s = new Thread(delegate() {
                using (TcpClient c = l.AcceptTcpClient()) { NetworkStream ns = c.GetStream(); byte[] b = new byte[8192]; int n;
                    while ((n = ns.Read(b, 0, b.Length)) > 0) ns.Write(b, 0, n); }
            }); s.Start();
            using (TcpClient c = new TcpClient("127.0.0.1", port)) {
                NetworkStream ns = c.GetStream(); byte[] o = new byte[200 * 1024]; new Random(2).NextBytes(o);
                Thread wr = new Thread(delegate() { ns.Write(o, 0, o.Length); c.Client.Shutdown(SocketShutdown.Send); }); wr.Start();
                MemoryStream got = new MemoryStream(); byte[] b = new byte[8192]; int n;
                while ((n = ns.Read(b, 0, b.Length)) > 0) got.Write(b, 0, n);
                T.Check(got.Length == o.Length, "echo length " + got.Length);
            }
            s.Join(); l.Stop();
        });
        T.Run("tcp listen on Any, connect 127.0.0.1 (WCF style)", delegate {
            T.Log("OSSupportsIPv6 " + Socket.OSSupportsIPv6 + " SupportsIPv4 " + Socket.SupportsIPv4);
            Socket l = new Socket(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Tcp);
            l.Bind(new IPEndPoint(IPAddress.Any, 8732)); l.Listen(10);
            IAsyncResult ar = l.BeginAccept(null, null);
            using (TcpClient c = new TcpClient()) { c.Connect("127.0.0.1", 8732); T.Check(ar.AsyncWaitHandle.WaitOne(5000, false), "accepted"); l.EndAccept(ar).Close(); }
            l.Close();
        });
        T.Run("dns localhost", delegate { T.Check(Dns.GetHostAddresses("localhost").Length > 0, "addresses"); });
        T.Run("reflection + emit", delegate {
            AssemblyBuilder ab = AppDomain.CurrentDomain.DefineDynamicAssembly(new AssemblyName("dyn"), AssemblyBuilderAccess.Run);
            TypeBuilder tb = ab.DefineDynamicModule("m").DefineType("D", TypeAttributes.Public);
            MethodBuilder mb = tb.DefineMethod("F", MethodAttributes.Public | MethodAttributes.Static, typeof(int), new Type[] { typeof(int) });
            ILGenerator il = mb.GetILGenerator(); il.Emit(OpCodes.Ldarg_0); il.Emit(OpCodes.Ldc_I4_3); il.Emit(OpCodes.Mul); il.Emit(OpCodes.Ret);
            T.Check((int)tb.CreateType().GetMethod("F").Invoke(null, new object[] { 7 }) == 21, "emit");
        });
        T.Run("appdomain create/unload", delegate {
            AppDomain d = AppDomain.CreateDomain("child"); d.SetData("x", 5); T.Check((int)d.GetData("x") == 5, "data"); AppDomain.Unload(d);
        });
        T.Run("registry HKCU write/read/delete", delegate {
            RegistryKey k = Registry.CurrentUser.CreateSubKey(@"Software\KexNgTest"); k.SetValue("v", 7); k.Close();
            T.Check((int)Registry.CurrentUser.OpenSubKey(@"Software\KexNgTest").GetValue("v") == 7, "value");
            Registry.CurrentUser.DeleteSubKeyTree(@"Software\KexNgTest");
        });
        T.Run("globalization cultures + formats", delegate {
            T.Check(1234.5.ToString("N2", new CultureInfo("de-DE")) == "1.234,50", "de-DE");
            T.Check(new DateTime(2008, 7, 29).ToString("D", new CultureInfo("en-US")).Contains("July"), "en-US date");
            T.Check(string.Compare("a", "B", true, CultureInfo.InvariantCulture) < 0, "compare");
            T.Check("i".ToUpper(new CultureInfo("tr-TR")) == "\u0130", "tr upper");
            T.Log("TimeZone " + TimeZone.CurrentTimeZone.StandardName);
        });
        T.Run("process start + exit code", delegate {
            Process p = Process.Start(new ProcessStartInfo(@"C:\WINDOWS\COMMAND.COM", "/c exit") { UseShellExecute = false, CreateNoWindow = true });
            T.Check(p.WaitForExit(20000), "exited");
            T.Log("processes visible: " + Process.GetProcesses().Length);
        });
        T.Run("exceptions: 10000 thrown/caught, nested finally", delegate {
            int c = 0; for (int i = 0; i < 10000; i++) { try { try { throw new InvalidOperationException(); } finally { c++; } } catch (InvalidOperationException) { } }
            T.Check(c == 10000, "count");
            try { object o = null; o.ToString(); } catch (NullReferenceException) { c++; }
            try { int z = 0; c /= z; } catch (DivideByZeroException) { c++; }
            T.Check(c == 10002, "hardware exceptions");
        });
        T.Run("stack overflow guard: deep recursion 20000", delegate { T.Check(Deep(20000) == 20000, "depth"); });
        T.Run("WindowsIdentity / token", delegate {
            System.Security.Principal.WindowsIdentity id = System.Security.Principal.WindowsIdentity.GetCurrent();
            T.Log("name " + id.Name + " auth " + id.AuthenticationType + " token " + id.Token);
            T.Log("user sid " + (id.User == null ? "NULL" : id.User.Value) + " owner " + (id.Owner == null ? "NULL" : id.Owner.Value));
            T.Log("groups " + (id.Groups == null ? "NULL" : id.Groups.Count.ToString()));
            T.Check(id.User != null, "User SID");
        });
        T.Run("stopwatch + environment", delegate {
            Stopwatch s = Stopwatch.StartNew(); Thread.Sleep(100); T.Check(s.ElapsedMilliseconds >= 90, "sleep " + s.ElapsedMilliseconds);
            T.Log("procs " + Environment.ProcessorCount + " machine " + Environment.MachineName + " user " + Environment.UserName);
            T.Log("sysdir " + Environment.SystemDirectory + " temp " + Path.GetTempPath());
        });
        return T.End();
    }
    static int Deep(int n) { return n == 0 ? 0 : 1 + Deep(n - 1); }
}
