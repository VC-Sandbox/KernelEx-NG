// exc.cs - does catching a managed exception work on the .NET 2.0 runtime? (C:\N20\EXC.TXT, raw bytes)
using System;
using System.IO;
class M {
    static FileStream f;
    static void Put(string s) { for (int i = 0; i < s.Length; i++) f.WriteByte((byte)(s[i] < 128 ? s[i] : '?')); f.WriteByte(13); f.WriteByte(10); f.Flush(); }
    static void Main() {
        f = new FileStream(@"C:\N20\EXC.TXT", FileMode.Create);
        Put("before throw");
        try { throw new InvalidOperationException("x"); } catch (Exception) { Put("caught 1"); }
        try { object o = null; o.ToString(); } catch (NullReferenceException) { Put("caught null deref"); }
        try { throw new InvalidOperationException("msg"); } catch (Exception e) { Put("message: " + e.Message); }
        Put("done"); f.Close();
    }
}
