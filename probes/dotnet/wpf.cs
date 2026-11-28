// wpf.cs - Windows Presentation Foundation 3.0/3.5: XAML parse, layout, offscreen render (RenderTargetBitmap ->
// PNG), text/fonts, a real Window shown for 3 s with an animation and data binding, dispatcher timers, then exit.
// C:\T\WPF.LOG, C:\T\WPF.PNG. Build /t:winexe.
using System;
using System.IO;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Markup;
using System.Windows.Media;
using System.Windows.Media.Animation;
using System.Windows.Media.Imaging;
using System.Windows.Shapes;
using System.Windows.Threading;

class P {
    [STAThread] static int Main() {
        T.Init("WPF");
        UIElement root = null;
        T.Run("XamlReader.Parse", delegate {
            root = (UIElement)XamlReader.Parse(
                "<StackPanel xmlns='http://schemas.microsoft.com/winfx/2006/xaml/presentation' Background='White' Width='300'>" +
                "<TextBlock FontSize='20' Text='KernelEx-NG WPF'/><Button Content='Button'/><CheckBox Content='Check' IsChecked='True'/>" +
                "<Ellipse Width='100' Height='50' Fill='Red'/><ProgressBar Height='10' Value='60'/></StackPanel>");
        });
        T.Run("layout measure/arrange", delegate {
            root.Measure(new Size(300, 400)); root.Arrange(new Rect(root.DesiredSize));
            T.Log("desired " + root.DesiredSize); T.Check(root.DesiredSize.Height > 50, "height");
        });
        T.Run("RenderTargetBitmap -> PNG", delegate {
            RenderTargetBitmap b = new RenderTargetBitmap(300, (int)root.DesiredSize.Height, 96, 96, PixelFormats.Pbgra32); b.Render(root);
            PngBitmapEncoder e = new PngBitmapEncoder(); e.Frames.Add(BitmapFrame.Create(b));
            using (FileStream f = File.Create(@"C:\T\WPF.PNG")) e.Save(f);
            int[] px = new int[1]; b.CopyPixels(new Int32Rect(150, (int)root.DesiredSize.Height - 30, 1, 1), px, 4, 0);
            T.Log("pixel in ellipse area " + px[0].ToString("X8"));
        });
        T.Run("fonts + FormattedText", delegate {
            T.Log("system font families " + Fonts.SystemFontFamilies.Count);
            FormattedText ft = new FormattedText("Hello", System.Globalization.CultureInfo.InvariantCulture, FlowDirection.LeftToRight,
                new Typeface("Arial"), 24, Brushes.Black); T.Check(ft.Width > 10, "width " + ft.Width);
        });
        T.Run("Application + Window 3 s with animation/binding", delegate {
            Application app = new Application(); app.ShutdownMode = ShutdownMode.OnExplicitShutdown;
            Window w = new Window(); w.Title = "KexNG WPF test"; w.Width = 400; w.Height = 300;
            StackPanel sp = new StackPanel(); Slider s = new Slider(); s.Maximum = 100; TextBlock tb = new TextBlock();
            tb.SetBinding(TextBlock.TextProperty, new System.Windows.Data.Binding("Value") { Source = s });
            Rectangle r = new Rectangle(); r.Height = 40; r.Fill = Brushes.Blue;
            sp.Children.Add(s); sp.Children.Add(tb); sp.Children.Add(r); w.Content = sp;
            int ticks = 0; bool rendered = false;
            w.ContentRendered += delegate { rendered = true; };
            DispatcherTimer t = new DispatcherTimer(); t.Interval = TimeSpan.FromMilliseconds(100);
            t.Tick += delegate { ticks++; s.Value = ticks * 3; if (ticks == 30) { w.Close(); app.Shutdown(); } };
            w.Loaded += delegate {
                r.BeginAnimation(FrameworkElement.WidthProperty, new DoubleAnimation(10, 380, TimeSpan.FromSeconds(2)));
                t.Start();
            };
            app.Run(w);
            T.Log("ticks " + ticks + " text " + tb.Text + " rendered " + rendered + " tier " + (RenderCapability.Tier >> 16));
            T.Check(rendered && ticks == 30 && tb.Text == "90", "window cycle");
        });
        return T.End();
    }
}
