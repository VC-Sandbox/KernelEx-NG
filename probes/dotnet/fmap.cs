// fmap.cs - probe: list the members of WPF 3.0's MS.Internal.FontCache.FileMapping (reflection, names and types only)
// to see what its Commit depends on. C:\T\FMAP.LOG
using System;
using System.Reflection;
using System.Runtime.InteropServices;
[StructLayout(LayoutKind.Sequential)] class MSX { public uint len = 64, load; public ulong phys, availPhys, page, availPage, virt, availVirt, ext; }
[StructLayout(LayoutKind.Sequential)] class MBI { public IntPtr Base, AllocBase; public uint AllocProtect; public IntPtr Size; public uint State, Protect, Type; }
[StructLayout(LayoutKind.Sequential)] class SYSI { public ushort arch, res; public uint page; public IntPtr min, max, mask; public uint n, type, gran; public ushort lvl, rev; }
class P {
    [DllImport("kernel32.dll", EntryPoint = "GlobalMemoryStatusEx", SetLastError = true)] static extern bool GMSX([In, Out] MSX m);
    [DllImport("kernel32.dll")] static extern void GetSystemInfo([Out] SYSI s);
    [DllImport("kernel32.dll")] static extern IntPtr VirtualQuery(IntPtr a, [Out] MBI m, IntPtr len);
    static IntPtr view;
    [DllImport("kernel32.dll")] static extern bool IsBadReadPtr(IntPtr p, IntPtr n);
    [DllImport("kernel32.dll")] static extern bool IsBadWritePtr(IntPtr p, IntPtr n);
    [DllImport("kernel32.dll", SetLastError = true)] static extern IntPtr VirtualAlloc(IntPtr a, IntPtr n, uint type, uint prot);
    static void Q(string when) { MBI m = new MBI(); IntPtr r = VirtualQuery(view, m, (IntPtr)28);
        T.Log(when + ": VirtualQuery " + r + " base " + m.Base.ToString("X8") + " allocbase " + m.AllocBase.ToString("X8") + " allocprot " + m.AllocProtect.ToString("X") +
              " size " + m.Size.ToString("X") + " state " + m.State.ToString("X") + " protect " + m.Protect.ToString("X") + " type " + m.Type.ToString("X")); }
    static int Main() {
        T.Init("FMAP");
        T.Run("FileMapping members", delegate {
            Type t = Type.GetType("MS.Internal.FontCache.FileMapping, PresentationCore, Version=3.0.0.0, Culture=neutral, PublicKeyToken=31bf3856ad364e35", true);
            foreach (MemberInfo m in t.GetMembers(BindingFlags.Instance | BindingFlags.Static | BindingFlags.Public | BindingFlags.NonPublic | BindingFlags.DeclaredOnly)) {
                string d = m.MemberType + " " + m.Name;
                if (m is FieldInfo) d += " : " + ((FieldInfo)m).FieldType.Name;
                if (m is MethodBase) { d += "("; foreach (ParameterInfo p in ((MethodBase)m).GetParameters()) d += p.ParameterType.Name + " "; d += ")"; }
                T.Log(d);
            }
        });
        T.Run("GlobalMemoryStatusEx + GetSystemInfo", delegate {
            MSX m = new MSX(); bool ok = GMSX(m);
            T.Log("GlobalMemoryStatusEx " + ok + " err " + Marshal.GetLastWin32Error() + " phys " + m.phys + " availPhys " + m.availPhys + " page " + m.page + " availPage " + m.availPage + " virt " + m.virt + " availVirt " + m.availVirt);
            SYSI s = new SYSI(); GetSystemInfo(s); T.Log("pagesize " + s.page + " gran " + s.gran + " min " + s.min + " max " + s.max);
        });
        BindingFlags all = BindingFlags.Instance | BindingFlags.Static | BindingFlags.Public | BindingFlags.NonPublic;
        Type ft = Type.GetType("MS.Internal.FontCache.FileMapping, PresentationCore, Version=3.0.0.0, Culture=neutral, PublicKeyToken=31bf3856ad364e35", true);
        object fm = null;
        T.Run("PageSize", delegate { T.Log("PageSize " + ft.GetField("PageSize", all).GetValue(null)); });
        T.Run("Create 'KexFmapTest' 16 MB", delegate {
            fm = Activator.CreateInstance(ft, true);
            try { ft.GetMethod("Create", all).Invoke(fm, new object[] { "KexFmapTest", (long)(16 << 20) }); } catch (TargetInvocationException e) { throw new Exception("Create", e.InnerException); }
            foreach (string f in new string[] { "_mappingHandle", "_viewHandle" }) {
                System.Runtime.InteropServices.SafeHandle h = (System.Runtime.InteropServices.SafeHandle)ft.GetField(f, all).GetValue(fm);
                T.Log(f + " " + (h == null ? "null" : h.DangerousGetHandle().ToString("X8") + " invalid " + h.IsInvalid));
                if (f == "_viewHandle") view = h.DangerousGetHandle();
            }
            Q("after Create");
        });
        foreach (long sz in new long[] { 4096, 65536, 1 << 20 }) {
            long z = sz;
            T.Run("Commit " + z, delegate {
                try { ft.GetMethod("Commit", all).Invoke(fm, new object[] { z }); } catch (TargetInvocationException e) { Q("after failed Commit " + z); throw new Exception("Commit", e.InnerException); }
                Q("after Commit " + z);
            });
        }
        T.Run("pages after commits", delegate {
            foreach (int off in new int[] { 0, 0x1000, 0x10000, 0xFF000 })
                T.Log("+" + off.ToString("X") + " badread " + IsBadReadPtr((IntPtr)(view.ToInt32() + off), (IntPtr)1) + " badwrite " + IsBadWritePtr((IntPtr)(view.ToInt32() + off), (IntPtr)1));
            IntPtr r = VirtualAlloc(view, (IntPtr)0x2000, 0x1000, 4);
            T.Log("own VirtualAlloc(view, 8K, COMMIT, RW) -> " + r.ToString("X8") + " err " + Marshal.GetLastWin32Error() + " badwrite now " + IsBadWritePtr(view, (IntPtr)1));
            Q("after own commit");
        });
        return T.End();
    }
}
