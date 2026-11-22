// form.cs - .NET 4 WinForms test: a window with a label, a button and a text box; writes C:\NETFORM.TXT once shown
using System;
using System.Drawing;
using System.Windows.Forms;
class F : Form {
    F() {
        Text = "KernelEx-NG .NET 4 WinForms"; ClientSize = new Size(360, 160);
        var l = new Label { Text = "Hello from .NET " + Environment.Version, AutoSize = true, Location = new Point(12, 12) };
        var t = new TextBox { Text = "type here", Location = new Point(12, 44), Width = 200 };
        var b = new Button { Text = "Click", Location = new Point(12, 80) };
        b.Click += (s, e) => l.Text = "Clicked: " + t.Text;
        Controls.AddRange(new Control[] { l, t, b });
        Shown += (s, e) => System.IO.File.WriteAllText(@"C:\NETFORM.TXT", "shown " + Environment.Version);
    }
    [STAThread] static void Main() {
        AppDomain.CurrentDomain.UnhandledException += (s, e) => System.IO.File.WriteAllText(@"C:\NETFORMX.TXT", "unhandled: " + e.ExceptionObject);
        try { Application.EnableVisualStyles(); Application.Run(new F()); }
        catch (Exception e) { System.IO.File.WriteAllText(@"C:\NETFORMX.TXT", e.ToString()); }
    }
}
