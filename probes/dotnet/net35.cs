// net35.cs - .NET 3.5 (System.Core, System.Xml.Linq, System.Data.DataSetExtensions): LINQ to Objects/XML/DataSet,
// expression trees, HashSet, ReaderWriterLockSlim, TimeZoneInfo, System.IO.Pipes-free parts, Func/Action. C:\T\NET35.LOG
using System;
using System.Collections.Generic;
using System.Data;
using System.Linq;
using System.Linq.Expressions;
using System.Threading;
using System.Xml.Linq;

static class Ext { public static string Twice(this string s) { return s + s; } }

class P {
    static int Main() {
        T.Init("NET35");
        T.Run("linq to objects 1M", () => {
            var q = Enumerable.Range(1, 1000000).Where(n => n % 3 == 0).Select(n => (long)n * n).Sum();
            T.Check(q == 111111277777611111L, "sum " + q);
            var g = (from n in Enumerable.Range(0, 1000) group n by n % 7 into k orderby k.Key select new { k.Key, C = k.Count() }).ToList();
            T.Check(g.Count == 7 && g[0].C == 143, "group");
            T.Check(Enumerable.Range(0, 100).OrderByDescending(x => x).Skip(10).First() == 89, "order/skip");
            T.Check(new[] { 3, 1, 2 }.Join(new[] { 1, 2 }, a => a, b => b, (a, b) => a).Count() == 2, "join");
        });
        T.Run("extension + lambda + anonymous types", () => {
            Func<int, int, int> add = (a, b) => a + b; T.Check(add(2, 3) == 5 && "ab".Twice() == "abab", "basic");
            var o = new { X = 1, Y = "y" }; T.Check(o.ToString() == "{ X = 1, Y = y }", "anon " + o);
        });
        T.Run("HashSet set ops 100k", () => {
            var a = new HashSet<int>(Enumerable.Range(0, 100000)); var b = new HashSet<int>(Enumerable.Range(50000, 100000));
            a.IntersectWith(b); T.Check(a.Count == 50000, "intersect");
        });
        T.Run("expression trees compile", () => {
            Expression<Func<int, int>> e = x => x * 2 + 1; T.Check(e.Compile()(20) == 41, "compiled");
            var p = Expression.Parameter(typeof(string), "s");
            var call = Expression.Lambda<Func<string, int>>(Expression.Property(p, "Length"), p).Compile();
            T.Check(call("abcd") == 4, "built");
        });
        T.Run("linq to xml", () => {
            var d = new XDocument(new XElement("r", Enumerable.Range(1, 500).Select(n => new XElement("i", new XAttribute("n", n)))));
            var s = d.ToString(); var d2 = XDocument.Parse(s);
            T.Check(d2.Root.Elements("i").Sum(x => (int)x.Attribute("n")) == 125250, "sum");
            T.Check((from x in d2.Descendants("i") where (int)x.Attribute("n") > 495 select x).Count() == 5, "query");
        });
        T.Run("linq to dataset", () => {
            var t = new DataTable(); t.Columns.Add("id", typeof(int)); t.Columns.Add("name", typeof(string));
            for (int i = 0; i < 1000; i++) t.Rows.Add(i, "n" + i);
            var q = t.AsEnumerable().Where(r => r.Field<int>("id") % 100 == 0).Select(r => r.Field<string>("name")).ToList();
            T.Check(q.Count == 10 && q[1] == "n100", "rows");
            T.Check(q.Count == t.AsEnumerable().CopyToDataTable().Select("id % 100 = 0").Length, "copy");
        });
        T.Run("ReaderWriterLockSlim 8 threads", () => {
            var l = new ReaderWriterLockSlim(); int v = 0;
            var th = Enumerable.Range(0, 8).Select(i => new Thread(() => {
                for (int k = 0; k < 5000; k++) { l.EnterWriteLock(); v++; l.ExitWriteLock(); l.EnterReadLock(); int x = v; l.ExitReadLock(); }
            })).ToList();
            th.ForEach(t => t.Start()); th.ForEach(t => t.Join()); T.Check(v == 40000, "v " + v);
        });
        T.Run("TimeZoneInfo", () => {
            var l = TimeZoneInfo.Local; T.Log("local " + l.Id + " / " + l.StandardName + " offset " + l.BaseUtcOffset);
            T.Log("system zones " + TimeZoneInfo.GetSystemTimeZones().Count);
            T.Check(TimeZoneInfo.ConvertTimeToUtc(new DateTime(2008, 1, 1, 12, 0, 0), TimeZoneInfo.Utc).Hour == 12, "utc");
        });
        T.Run("DateTimeOffset", () => { var d = new DateTimeOffset(2008, 7, 29, 0, 0, 0, TimeSpan.FromHours(2)); T.Check(d.UtcDateTime.Hour == 22, "utc"); });
        T.Run("parallel-ish: 64 threads LINQ", () => {
            long total = 0; var th = new List<Thread>();
            for (int i = 0; i < 64; i++) { var t = new Thread(() => Interlocked.Add(ref total, Enumerable.Range(0, 10000).Sum())); th.Add(t); t.Start(); }
            th.ForEach(t => t.Join()); T.Check(total == 64L * 49995000, "total");
        });
        return T.End();
    }
}
