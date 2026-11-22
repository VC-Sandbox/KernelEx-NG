/* attach.c - ATTACH.EXE <pid hex> <log>: attaches the Win32 debugger to a running (hung) process and logs, for
 * every thread, its registers and a stack scan mapped to modules; then the module list. Windows 98 cannot detach
 * a debugger: the process ends when ATTACH.EXE exits. Windows 95 program (KernelEx leaves it alone). */
#include <windows.h>
#include <tlhelp32.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
static FILE *o; static HANDLE hp; static DWORD pid;
typedef struct { DWORD base, size; char name[64]; } MOD;
static MOD mods[256]; static int nmods;
static void snap_mods(void)
{
    HANDLE s = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, pid); MODULEENTRY32 m; m.dwSize = sizeof(m); nmods = 0;
    if (s == INVALID_HANDLE_VALUE) return;
    if (Module32First(s, &m)) do {
        if (nmods < 256) { mods[nmods].base = (DWORD)m.modBaseAddr; mods[nmods].size = m.modBaseSize; lstrcpynA(mods[nmods].name, m.szModule, 64); nmods++; }
    } while (Module32Next(s, &m));
    CloseHandle(s);
}
static const char *where(DWORD a, DWORD *off)
{
    int i;
    for (i = 0; i < nmods; i++) if (a >= mods[i].base && a < mods[i].base + mods[i].size) { *off = a - mods[i].base; return mods[i].name; }
    return NULL;
}
static BOOL rd(DWORD a, void *b, DWORD n) { DWORD got = 0; return ReadProcessMemory(hp, (LPCVOID)a, b, n, &got) && got == n; }
static void dump(HANDLE th, DWORD tid)
{
    CONTEXT c; DWORD st[256], j, off; const char *m;
    c.ContextFlags = CONTEXT_FULL;
    if (!GetThreadContext(th, &c)) { fprintf(o, "thread %08lx: no context (%lu)\n", tid, GetLastError()); return; }
    m = where(c.Eip, &off);
    fprintf(o, "thread %08lx eip %08lx (%s+%lx) esp %08lx ebp %08lx eax %08lx ebx %08lx ecx %08lx edx %08lx esi %08lx edi %08lx\n",
            tid, c.Eip, m ? m : "?", m ? off : 0, c.Esp, c.Ebp, c.Eax, c.Ebx, c.Ecx, c.Edx, c.Esi, c.Edi);
    if (rd(c.Esp, st, sizeof(st))) for (j = 0; j < 256; j++) { m = where(st[j], &off); if (m) fprintf(o, "    stack+%03lx %08lx %s+%lx\n", j * 4, st[j], m, off); }
}
int main(int argc, char **argv)
{
    DEBUG_EVENT ev; int i, settled = 0;
    if (argc < 3) return 1;
    pid = strtoul(argv[1], NULL, 16); o = fopen(argv[2], "w"); if (!o) return 2;
    if (!DebugActiveProcess(pid)) { fprintf(o, "DebugActiveProcess %lu\n", GetLastError()); return 3; }
    hp = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
    snap_mods();
    while (WaitForDebugEvent(&ev, 5000)) {
        if (ev.dwDebugEventCode == CREATE_PROCESS_DEBUG_EVENT) dump(ev.u.CreateProcessInfo.hThread, ev.dwThreadId);
        else if (ev.dwDebugEventCode == CREATE_THREAD_DEBUG_EVENT) dump(ev.u.CreateThread.hThread, ev.dwThreadId);
        else if (ev.dwDebugEventCode == LOAD_DLL_DEBUG_EVENT && ev.u.LoadDll.hFile) CloseHandle(ev.u.LoadDll.hFile);
        else if (ev.dwDebugEventCode == EXCEPTION_DEBUG_EVENT) { fprintf(o, "exception %08lx at %08lx thread %08lx\n", ev.u.Exception.ExceptionRecord.ExceptionCode, (DWORD)ev.u.Exception.ExceptionRecord.ExceptionAddress, ev.dwThreadId); if (++settled > 3) break; }
        fflush(o);
        ContinueDebugEvent(ev.dwProcessId, ev.dwThreadId, DBG_CONTINUE);
        if (ev.dwDebugEventCode == EXCEPTION_DEBUG_EVENT && settled) break;
    }
    fprintf(o, "modules:\n");
    for (i = 0; i < nmods; i++) fprintf(o, "  %08lx %08lx %s\n", mods[i].base, mods[i].size, mods[i].name);
    fclose(o);
    return 0;
}
