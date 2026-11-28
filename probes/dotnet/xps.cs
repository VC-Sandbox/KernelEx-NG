// xps.cs - XPS (ReachFramework / System.Printing): write a 3-page FixedDocument to an XPS package, read it back,
// list print queues. C:\T\XPS.LOG, C:\T\TEST.XPS. Build /t:winexe.
using System;
using System.IO;
using System.IO.Packaging;
using System.Printing;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Documents;
using System.Windows.Markup;
using System.Windows.Xps.Packaging;

class P {
    [STAThread] static int Main() {
        T.Init("XPS");
        string path = @"C:\T\TEST.XPS";
        T.Run("write 3-page XPS", delegate {
            if (File.Exists(path)) File.Delete(path);
            FixedDocument doc = new FixedDocument();
            for (int i = 1; i <= 3; i++) {
                FixedPage pg = new FixedPage(); pg.Width = 816; pg.Height = 1056;
                TextBlock tb = new TextBlock(); tb.Text = "Page " + i; tb.FontSize = 40; FixedPage.SetLeft(tb, 96); FixedPage.SetTop(tb, 96);
                pg.Children.Add(tb); PageContent pc = new PageContent(); ((IAddChild)pc).AddChild(pg); doc.Pages.Add(pc);
            }
            using (XpsDocument x = new XpsDocument(path, FileAccess.ReadWrite))
                XpsDocument.CreateXpsDocumentWriter(x).Write(doc);
            T.Log("size " + new FileInfo(path).Length);
        });
        T.Run("read XPS back", delegate {
            using (XpsDocument x = new XpsDocument(path, FileAccess.Read)) {
                FixedDocumentSequence s = x.GetFixedDocumentSequence();
                T.Check(s.DocumentPaginator.PageCount == 3, "pages " + s.DocumentPaginator.PageCount);
            }
        });
        T.Run("System.IO.Packaging zip parts", delegate {
            using (Package p = Package.Open(@"C:\T\TEST.ZIP", FileMode.Create)) {
                PackagePart pp = p.CreatePart(new Uri("/a.txt", UriKind.Relative), "text/plain");
                using (StreamWriter w = new StreamWriter(pp.GetStream())) w.Write("hi");
            }
            using (Package p = Package.Open(@"C:\T\TEST.ZIP", FileMode.Open))
                T.Check(p.GetPart(new Uri("/a.txt", UriKind.Relative)) != null, "part");
        });
        T.Run("LocalPrintServer queues", delegate {
            using (LocalPrintServer s = new LocalPrintServer()) foreach (PrintQueue q in s.GetPrintQueues()) T.Log("queue " + q.Name);
        });
        return T.End();
    }
}
