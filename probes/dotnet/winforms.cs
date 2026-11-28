// winforms.cs - Windows Forms / GDI+ (.NET 2.0): form with common controls shown 3 s, Timer, GDI+ drawing to a
// Bitmap saved as PNG/JPEG, Graphics text, a DataGridView with 1000 rows, Invoke from a worker thread. C:\T\WINFORMS.LOG
using System;
using System.Drawing;
using System.Drawing.Drawing2D;
using System.Drawing.Imaging;
using System.Threading;
using System.Windows.Forms;

class P {
    [STAThread] static int Main() {
        T.Init("WINFORMS");
        T.Run("GDI+ bitmap draw + PNG/JPEG", delegate {
            using (Bitmap b = new Bitmap(320, 200)) using (Graphics g = Graphics.FromImage(b)) {
                g.SmoothingMode = SmoothingMode.AntiAlias; g.Clear(Color.White);
                using (LinearGradientBrush br = new LinearGradientBrush(new Rectangle(0, 0, 320, 200), Color.Red, Color.Blue, 45f)) g.FillEllipse(br, 10, 10, 300, 180);
                g.DrawString("KernelEx-NG", new Font("Arial", 20), Brushes.Black, 60, 80);
                b.Save(@"C:\T\GDIP.PNG", ImageFormat.Png); b.Save(@"C:\T\GDIP.JPG", ImageFormat.Jpeg);
                T.Check(b.GetPixel(160, 100).ToArgb() != Color.White.ToArgb(), "drawn");
            }
            using (Image i = Image.FromFile(@"C:\T\GDIP.PNG")) T.Check(i.Width == 320, "reload");
        });
        T.Run("form with controls 3 s, timer, worker Invoke", delegate {
            Form f = new Form(); f.Text = "KexNG WinForms test"; f.Size = new Size(500, 400);
            TextBox tb = new TextBox(); tb.Dock = DockStyle.Top; ComboBox cb = new ComboBox(); cb.Dock = DockStyle.Top;
            cb.Items.AddRange(new object[] { "a", "b" }); cb.SelectedIndex = 1;
            DataGridView dg = new DataGridView(); dg.Dock = DockStyle.Fill; dg.Columns.Add("c1", "N"); dg.Columns.Add("c2", "Square");
            for (int i = 0; i < 1000; i++) dg.Rows.Add(i, i * i);
            ProgressBar pb = new ProgressBar(); pb.Dock = DockStyle.Bottom;
            f.Controls.Add(dg); f.Controls.Add(cb); f.Controls.Add(tb); f.Controls.Add(pb);
            int ticks = 0; string fromWorker = null;
            System.Windows.Forms.Timer t = new System.Windows.Forms.Timer(); t.Interval = 100;
            t.Tick += delegate { ticks++; pb.Value = Math.Min(100, ticks * 4); dg.FirstDisplayedScrollingRowIndex = ticks * 20; if (ticks == 30) f.Close(); };
            f.Shown += delegate {
                t.Start();
                new Thread(delegate() { f.Invoke((MethodInvoker)delegate { tb.Text = "from worker"; fromWorker = tb.Text; }); }).Start();
            };
            Application.Run(f);
            T.Check(ticks == 30 && fromWorker == "from worker", "ticks " + ticks + " worker " + fromWorker);
        });
        return T.End();
    }
}
