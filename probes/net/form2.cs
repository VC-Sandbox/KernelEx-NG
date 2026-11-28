// form2.cs - .NET 2.0 (C# 2) WinForms test: label, text box, button; writes C:\N20\FORM2.TXT once shown
using System;
using System.Drawing;
using System.Windows.Forms;
class F : Form {
    Label l; TextBox t;
    F() {
        Text = "KernelEx-NG .NET 2.0 WinForms"; ClientSize = new Size(360, 160);
        l = new Label(); l.Text = "Hello from .NET " + Environment.Version; l.AutoSize = true; l.Location = new Point(12, 12);
        t = new TextBox(); t.Text = "type here"; t.Location = new Point(12, 44); t.Width = 200;
        Button b = new Button(); b.Text = "Click"; b.Location = new Point(12, 80);
        b.Click += delegate { l.Text = "Clicked: " + t.Text; };
        Controls.AddRange(new Control[] { l, t, b });
        Shown += delegate { System.IO.File.WriteAllText(@"C:\N20\FORM2.TXT", "shown " + Environment.Version); };
    }
    [STAThread] static void Main() {
        try { Application.EnableVisualStyles(); Application.Run(new F()); }
        catch (Exception e) { System.IO.File.WriteAllText(@"C:\N20\FORM2X.TXT", e.ToString()); }
    }
}
