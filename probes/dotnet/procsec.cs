// procsec.cs - probe: the process security calls WF's DebugController.InitializeProcessSecurity is likely to make
// (GetSecurityInfo / GetKernelObjectSecurity on the process and its token), through KernelEx. C:\T\PROCSEC.LOG
using System;
using System.Runtime.InteropServices;
class P {
    [DllImport("advapi32.dll", SetLastError = true)] static extern uint GetSecurityInfo(IntPtr h, int type, int info, out IntPtr owner, out IntPtr group, out IntPtr dacl, out IntPtr sacl, out IntPtr sd);
    [DllImport("advapi32.dll", SetLastError = true)] static extern bool GetKernelObjectSecurity(IntPtr h, int info, IntPtr sd, int len, out int need);
    [DllImport("advapi32.dll", SetLastError = true)] static extern bool OpenProcessToken(IntPtr p, int access, out IntPtr tok);
    [DllImport("kernel32.dll")] static extern IntPtr GetCurrentProcess();
    static int Main() {
        T.Init("PROCSEC");
        T.Run("process GetSecurityInfo (owner, group, DACL)", delegate {
            IntPtr o, g, d, s, sd; uint r = GetSecurityInfo(GetCurrentProcess(), 6, 7, out o, out g, out d, out s, out sd);
            T.Log("result " + r + " owner " + o + " group " + g + " dacl " + d + " sd " + sd);
        });
        T.Run("process GetKernelObjectSecurity", delegate {
            int need; IntPtr b = Marshal.AllocHGlobal(4096); bool ok = GetKernelObjectSecurity(GetCurrentProcess(), 7, b, 4096, out need);
            T.Log("ok " + ok + " err " + Marshal.GetLastWin32Error() + " need " + need);
        });
        T.Run("token GetSecurityInfo", delegate {
            IntPtr t; bool ok = OpenProcessToken(GetCurrentProcess(), 0x20008, out t); T.Log("OpenProcessToken " + ok + " " + t);
            IntPtr o, g, d, s, sd; uint r = GetSecurityInfo(t, 6, 7, out o, out g, out d, out s, out sd);
            T.Log("result " + r + " owner " + o + " group " + g + " dacl " + d + " sd " + sd);
        });
        T.Run("System.Diagnostics.Process.GetCurrentProcess().Handle + SafeHandle", delegate {
            System.Diagnostics.Process p = System.Diagnostics.Process.GetCurrentProcess(); T.Log("handle " + p.Handle + " id " + p.Id + " session " + p.SessionId);
        });
        return T.End();
    }
}
