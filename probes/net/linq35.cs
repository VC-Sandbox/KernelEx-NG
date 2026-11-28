// linq35.cs - .NET 3.5 (C# 3) test: LINQ to Objects, lambdas, anonymous types, extension methods, HashSet<T>
// (System.Core.dll) and LINQ to XML (System.Xml.Linq.dll), all from the GAC; writes C:\N20\LINQ35.TXT
// Build in the VM with the 3.5 compiler:
//   C:\WINDOWS\Microsoft.NET\Framework\v3.5\csc.exe /out:C:\N20\LINQ35.EXE /r:System.Core.dll /r:System.Xml.Linq.dll linq35.cs
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Xml.Linq;

static class Ext { public static string Twice(this string s) { return s + s; } }

class P {
    static int Main() {
        using (StreamWriter o = new StreamWriter(@"C:\N20\LINQ35.TXT")) {
            try {
                var nums = Enumerable.Range(1, 20);
                var evens = nums.Where(n => n % 2 == 0).Select(n => n * n).ToList();
                o.WriteLine("squares of evens: " + string.Join(",", evens.Select(n => n.ToString()).ToArray()));
                var groups = from n in nums group n by n % 3 into g orderby g.Key select new { Key = g.Key, Sum = g.Sum() };
                foreach (var g in groups) o.WriteLine("mod 3 = " + g.Key + ": sum " + g.Sum);
                var set = new HashSet<string>(new[] { "a", "b", "a", "c" });
                o.WriteLine("HashSet count: " + set.Count);
                o.WriteLine("extension: " + "ab".Twice());
                XDocument d = new XDocument(new XElement("root",
                    nums.Take(3).Select(n => new XElement("item", new XAttribute("n", n)))));
                o.WriteLine("xml: " + d.ToString(SaveOptions.DisableFormatting));
                int total = (from e in d.Root.Elements("item") select (int)e.Attribute("n")).Sum();
                o.WriteLine("xml sum: " + total);
                o.WriteLine("runtime: " + Environment.Version + " on " + Environment.OSVersion);
                o.WriteLine("OK");
                return 0;
            } catch (Exception e) { o.WriteLine("EXCEPTION " + e); return 1; }
        }
    }
}
