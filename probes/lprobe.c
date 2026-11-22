/* lprobe.c - measures how Windows 98 itself handles private memory placed in the shared arena (2-3 GB)
 * with VirtualAlloc(..., 0x08000000 = VA_SHARED). Plain Win32 (subsystem 4.0): kexnt stays out.
 * Writes A:\LP.TXT. Modes: (none) = parent tests; "child <mode> <outfile>" = child that allocates and then
 * exits (exit), waits to be killed (wait), or faults (crash). */
#include <windows.h>
#define VA_SHARED 0x08000000
static HANDLE g_log;
static void L(const char *f, ...)
{
    char b[512]; DWORD n; va_list a; va_start(a, f); n = wvsprintfA(b, f, a); va_end(a);
    WriteFile(g_log, b, n, &n, NULL); FlushFileBuffers(g_log);
}
static void Q(const char *what, void *p)
{
    MEMORY_BASIC_INFORMATION m; ZeroMemory(&m, sizeof(m));
    if (!VirtualQuery(p, &m, sizeof(m))) { L("  %s %08lx: VirtualQuery failed %lu\r\n", what, (DWORD)p, GetLastError()); return; }
    L("  %s %08lx: base %08lx allocbase %08lx size %08lx state %lx protect %lx type %lx\r\n", what, (DWORD)p,
      (DWORD)m.BaseAddress, (DWORD)m.AllocationBase, (DWORD)m.RegionSize, m.State, m.Protect, m.Type);
}
static void arena(const char *what)
{
    DWORD a = 0x80000000UL, fr = 0, mx = 0; MEMORY_BASIC_INFORMATION m;
    while (a < 0xC0000000UL && VirtualQuery((void *)a, &m, sizeof(m)) && m.RegionSize) {
        if (m.State == MEM_FREE) { fr += m.RegionSize; if (m.RegionSize > mx) mx = m.RegionSize; }
        a = (DWORD)m.BaseAddress + m.RegionSize;
    }
    L("%s: shared arena free %lu KB, largest %lu KB\r\n", what, fr >> 10, mx >> 10);
}
static int child(const char *mode, const char *out)
{
    BYTE *p = (BYTE *)VirtualAlloc(NULL, 8 << 20, MEM_RESERVE | VA_SHARED, PAGE_NOACCESS);
    HANDLE f; DWORD n; char b[32];
    if (!p || !VirtualAlloc(p, 1 << 20, MEM_COMMIT, PAGE_READWRITE)) return 3;
    FillMemory(p, 1 << 20, 0xC5);
    n = wsprintfA(b, "%08lx", (DWORD)p);
    f = CreateFileA(out, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, 0, NULL);
    WriteFile(f, b, n, &n, NULL); CloseHandle(f);
    if (!lstrcmpA(mode, "exit")) return 0;
    if (!lstrcmpA(mode, "crash")) {
        BYTE *r = (BYTE *)VirtualAlloc(NULL, 65536, MEM_RESERVE, PAGE_NOACCESS);
        SetErrorMode(SEM_NOGPFAULTERRORBOX | SEM_FAILCRITICALERRORS);
        *(volatile BYTE *)r = 1;
        return 4;
    }
    Sleep(INFINITE);
    return 0;
}
static DWORD run_child(const char *mode, int kill)
{
    char cmd[MAX_PATH + 64], exe[MAX_PATH], addr[32]; STARTUPINFOA si; PROCESS_INFORMATION pi; DWORD code = 99, n = 0, t;
    HANDLE f; BYTE *p = NULL;
    GetModuleFileNameA(NULL, exe, MAX_PATH);
    DeleteFileA("C:\\LPCHILD.TXT");
    wsprintfA(cmd, "\"%s\" child %s C:\\LPCHILD.TXT", exe, mode);
    ZeroMemory(&si, sizeof(si)); si.cb = sizeof(si);
    if (!CreateProcessA(NULL, cmd, NULL, NULL, FALSE, 0, NULL, NULL, &si, &pi)) { L("child %s: CreateProcess %lu\r\n", mode, GetLastError()); return 0; }
    for (t = 0; t < 200; t++) {                  /* wait for the address file */
        f = CreateFileA("C:\\LPCHILD.TXT", GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, 0, NULL);
        if (f != INVALID_HANDLE_VALUE) { ReadFile(f, addr, 8, &n, NULL); CloseHandle(f); if (n == 8) break; }
        if (WaitForSingleObject(pi.hProcess, 50) == WAIT_OBJECT_0) break;
    }
    if (n == 8) { addr[8] = 0; { DWORD v = 0; int i; for (i = 0; i < 8; i++) v = v * 16 + (addr[i] <= '9' ? addr[i] - '0' : (addr[i] | 32) - 'a' + 10); p = (BYTE *)v; } }
    L("child %s: its memory at %08lx\r\n", mode, (DWORD)p);
    if (p) { Q("while the child lives", p); L("  first byte read from here: %02x\r\n", IsBadReadPtr(p, 1) ? 0x100 : p[0]); }
    if (kill) { L("  TerminateProcess: %d\r\n", TerminateProcess(pi.hProcess, 7)); }
    t = WaitForSingleObject(pi.hProcess, 20000); GetExitCodeProcess(pi.hProcess, &code);
    L("  child ended: wait %lu exit code %lu\r\n", t, code);
    CloseHandle(pi.hProcess); CloseHandle(pi.hThread);
    Sleep(500);
    if (p) {
        Q("after the child ended", p);
        if (!IsBadReadPtr(p, 1)) L("  first byte now: %02x\r\n", p[0]);
    }
    return (DWORD)p;
}
int main(int argc, char **argv)
{
    BYTE *p, *q, *r; DWORD old, i, bad;
    if (argc >= 4 && !lstrcmpA(argv[1], "child")) return child(argv[2], argv[3]);
    g_log = CreateFileA("A:\\LP.TXT", GENERIC_WRITE, FILE_SHARE_READ, NULL, CREATE_ALWAYS, 0, NULL);
    L("lprobe: Windows 98 and VirtualAlloc(VA_SHARED)\r\n");
    arena("start");
    /* 1. reserve in the shared arena */
    p = (BYTE *)VirtualAlloc(NULL, 2 << 20, MEM_RESERVE | VA_SHARED, PAGE_NOACCESS);
    L("1 reserve 2 MB VA_SHARED: %08lx error %lu\r\n", (DWORD)p, p ? 0 : GetLastError()); if (p) Q("reserved", p);
    if (p) {
        /* 2. commit part of it without the flag */
        q = (BYTE *)VirtualAlloc(p + 0x10000, 0x10000, MEM_COMMIT, PAGE_READWRITE);
        L("2 commit 64 KB inside (no flag): %08lx error %lu\r\n", (DWORD)q, q ? 0 : GetLastError());
        if (!q) { q = (BYTE *)VirtualAlloc(p + 0x10000, 0x10000, MEM_COMMIT | VA_SHARED, PAGE_READWRITE);
                  L("2b commit with VA_SHARED: %08lx error %lu\r\n", (DWORD)q, q ? 0 : GetLastError()); }
        if (q) {
            FillMemory(q, 0x10000, 0x5A); for (bad = 0, i = 0; i < 0x10000; i++) if (q[i] != 0x5A) bad++;
            L("  write/read 64 KB: %lu wrong\r\n", bad); Q("committed", q);
            L("3 decommit: %d\r\n", VirtualFree(q, 0x10000, MEM_DECOMMIT)); Q("decommitted", q);
            r = (BYTE *)VirtualAlloc(q, 0x10000, MEM_COMMIT, PAGE_READWRITE);
            L("  recommit: %08lx, first byte %02x\r\n", (DWORD)r, r ? r[0] : 0x100);
            L("  VirtualProtect READONLY: %d (old %lx)\r\n", VirtualProtect(q, 4096, PAGE_READONLY, &old), old); Q("protected", q);
        }
        L("4 release: %d error %lu\r\n", VirtualFree(p, 0, MEM_RELEASE), GetLastError()); Q("released", p);
    }
    /* 5. explicit addresses in the shared arena */
    q = (BYTE *)VirtualAlloc(NULL, 4 << 20, MEM_RESERVE | VA_SHARED, PAGE_NOACCESS);
    L("5 reserve 4 MB: %08lx\r\n", (DWORD)q);
    if (q) {
        BYTE *al = (BYTE *)(((DWORD)q + 0x1FFFFF) & ~0x1FFFFFUL);
        VirtualFree(q, 0, MEM_RELEASE);
        r = (BYTE *)VirtualAlloc(al, 2 << 20, MEM_RESERVE, PAGE_NOACCESS);
        L("  explicit %08lx without the flag: %08lx error %lu\r\n", (DWORD)al, (DWORD)r, r ? 0 : GetLastError());
        if (r) { Q("explicit no flag", r); VirtualFree(r, 0, MEM_RELEASE); }
        r = (BYTE *)VirtualAlloc(al, 2 << 20, MEM_RESERVE | VA_SHARED, PAGE_NOACCESS);
        L("  explicit %08lx with VA_SHARED: %08lx error %lu\r\n", (DWORD)al, (DWORD)r, r ? 0 : GetLastError());
        if (r) { Q("explicit flag", r);
                 L("  commit in it: %08lx\r\n", (DWORD)VirtualAlloc(r, 4096, MEM_COMMIT, PAGE_READWRITE));
                 L("  release: %d\r\n", VirtualFree(r, 0, MEM_RELEASE)); }
        /* reserve+commit in one call */
        r = (BYTE *)VirtualAlloc(NULL, 0x40000, MEM_RESERVE | MEM_COMMIT | VA_SHARED, PAGE_READWRITE);
        L("  reserve+commit 256 KB in one call: %08lx\r\n", (DWORD)r); if (r) { Q("rc", r); r[5] = 1; VirtualFree(r, 0, MEM_RELEASE); }
    }
    /* 6. what happens to it when its process ends */
    arena("before children");
    {   DWORD a1 = run_child("exit", 0), a2, a3;
        arena("after child exit");
        a2 = run_child("wait", 1);
        arena("after child killed");
        a3 = run_child("crash", 0);
        arena("after child crashed");
        /* can another process free it? */
        if (a1) { MEMORY_BASIC_INFORMATION m; VirtualQuery((void *)a1, &m, sizeof(m));
                  if (m.State != MEM_FREE) { L("7 freeing the exited child's block from here: %d error %lu\r\n", VirtualFree((void *)a1, 0, MEM_RELEASE), GetLastError()); Q("after", (void *)a1); } }
        if (a2) { MEMORY_BASIC_INFORMATION m; VirtualQuery((void *)a2, &m, sizeof(m));
                  if (m.State != MEM_FREE) { L("7 freeing the killed child's block from here: %d error %lu\r\n", VirtualFree((void *)a2, 0, MEM_RELEASE), GetLastError()); Q("after", (void *)a2); } }
        if (a3) { MEMORY_BASIC_INFORMATION m; VirtualQuery((void *)a3, &m, sizeof(m));
                  if (m.State != MEM_FREE) { L("7 freeing the crashed child's block from here: %d error %lu\r\n", VirtualFree((void *)a3, 0, MEM_RELEASE), GetLastError()); Q("after", (void *)a3); } }
        arena("end");
    }
    L("done\r\n");
    CloseHandle(g_log);
    return 0;
}
