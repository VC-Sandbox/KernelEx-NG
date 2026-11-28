// min5.cs - .NET 2.0 feature steps, results as raw bytes (C:\N20\MIN5.TXT)
using System;
using System.IO;
class M {
    static FileStream f;
    static void Put(string s) { for (int i = 0; i < s.Length; i++) f.WriteByte((byte)(s[i] < 128 ? s[i] : '?')); f.WriteByte(13); f.WriteByte(10); f.Flush(); }
    delegate string Func();
    static void Step(string n, Func fn) {
        Put(n + " ...");
        try { Put(n + ": " + fn()); }
        catch (Exception e) { Put(n + " FAILED " + e.GetType().FullName); try { Put("  " + e.Message); } catch { } try { Put("  " + e.StackTrace); } catch { } }
    }
    static void Main() {
        f = new FileStream(@"C:\N20\MIN5.TXT", FileMode.Create);
        Step("Regex", delegate { return System.Text.RegularExpressions.Regex.Replace("a1b22", "[0-9]+", "#"); });
        Step("Xml", delegate { System.Xml.XmlDocument d = new System.Xml.XmlDocument(); d.LoadXml("<a b='1'/>"); return d.DocumentElement.GetAttribute("b"); });
        Step("Dictionary", delegate { System.Collections.Generic.Dictionary<string,int> d = new System.Collections.Generic.Dictionary<string,int>(); d["x"] = 5; return d["x"].ToString(); });
        Step("Thread", delegate { int r = 0; System.Threading.Thread t = new System.Threading.Thread(delegate() { r = 42; }); t.Start(); t.Join(); return r.ToString(); });
        Step("Http", delegate { System.Net.WebClient w = new System.Net.WebClient(); return w.DownloadString("http://10.0.2.2:8000/cmds.txt").Length.ToString(); });
        Put("done"); f.Close();
    }
}
