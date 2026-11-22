// min.cs - .NET 4 test using only mscorlib -> C:\NETMIN.TXT
class M { static void Main() { System.IO.File.WriteAllText(@"C:\NETMIN.TXT", "mscorlib only: CLR " + System.Environment.Version + " OS " + System.Environment.OSVersion + " 2+2=" + (2 + 2)); } }
