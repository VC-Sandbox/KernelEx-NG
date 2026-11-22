/* dbg.c - DBG.EXE <log file> <command line>: runs a program under the Win32 debug API (Windows 98 has it) and
 * logs every exception (first and second chance) with registers, the module it is in, a raw stack scan mapped
 * to modules, C++ exception type names (MSVC e06d7363: ThrowInfo -> CatchableTypeArray -> TypeDescriptor),
 * OutputDebugString text, DLL loads and the exit code. A Windows 95 program itself: KernelEx/kexnt leave it alone.
 * Second-chance exceptions are passed on, so the program dies the way it would without the debugger. */
#include <windows.h>
#include <tlhelp32.h>
#include <stdio.h>
#include <string.h>

static FILE *o; static HANDLE hp; static DWORD pid;
static struct { DWORD pid; HANDLE h; } procs[32]; static int nprocs; static int follow;
static void cur(DWORD p) { int i; pid = p; for (i = 0; i < nprocs; i++) if (procs[i].pid == p) hp = procs[i].h; }
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
    if (a >= 0xBFF70000 && a < 0xC0000000) { *off = a - 0xBFF70000; return "KERNEL32(9x)"; }
    return NULL;
}
static BOOL rd(DWORD a, void *b, DWORD n) { DWORD got = 0; return ReadProcessMemory(hp, (LPCVOID)a, b, n, &got) && got == n; }
static void cxx(DWORD ti)
{
    DWORD t[4], cta[8], ct[2], i, cnt; char name[128];
    if (!rd(ti, t, 16)) { fprintf(o, "    (ThrowInfo unreadable)\n"); return; }
    if (!rd(t[3], &cnt, 4) || cnt > 8) return;
    rd(t[3] + 4, cta, cnt * 4);
    for (i = 0; i < cnt; i++) {
        if (!rd(cta[i], ct, 8)) continue;
        memset(name, 0, sizeof(name)); rd(ct[1] + 8, name, sizeof(name) - 1);
        fprintf(o, "    C++ type: %s\n", name);
    }
}
static void ascii_at(DWORD a)
{
    unsigned char b[160]; int i; WCHAR *w = (WCHAR *)b;
    if (!rd(a, b, sizeof(b))) return;
    fprintf(o, "      [%08lx] \"", a);
    if (b[1] == 0 && b[0]) { for (i = 0; i < 70 && w[i]; i++) fputc(w[i] < 127 && w[i] >= 32 ? (char)w[i] : '.', o); fprintf(o, "\" (UTF-16)\n"); }
    else { for (i = 0; i < 140 && b[i]; i++) fputc(b[i] < 127 && b[i] >= 32 ? b[i] : '.', o); fprintf(o, "\"\n"); }
}
int main(int argc, char **argv)
{
    STARTUPINFOA si; PROCESS_INFORMATION pi; DEBUG_EVENT ev; char *cmd; int nex = 0, i;
    HANDLE threads[64]; DWORD tids[64]; int nth = 0;
    if (argc < 3) return 1;
    follow = GetEnvironmentVariableA("DBGFOLLOW", NULL, 0) > 0 || argv[1][0] == '+';
    o = fopen(argv[1] + (argv[1][0] == '+'), "w"); if (!o) return 2;
    {   /* command line after "DBG.EXE <log>" */
        char *p = GetCommandLineA(); int k;
        for (k = 0; k < 2; k++) {
            while (*p == ' ') p++;
            if (*p == '"') { p++; while (*p && *p != '"') p++; if (*p) p++; } else while (*p && *p != ' ') p++;
        }
        while (*p == ' ') p++;
        cmd = p;
    }
    ZeroMemory(&si, sizeof(si)); si.cb = sizeof(si);
    fprintf(o, "cmd: %s\n", cmd); fflush(o);
    if (!CreateProcessA(NULL, cmd, NULL, NULL, FALSE, follow ? DEBUG_PROCESS : DEBUG_ONLY_THIS_PROCESS, NULL, NULL, &si, &pi)) { fprintf(o, "CreateProcess %lu\n", GetLastError()); return 3; }
    hp = pi.hProcess; pid = pi.dwProcessId;
    for (;;) {
        DWORD cont = DBG_CONTINUE;
        if (!WaitForDebugEvent(&ev, 600000)) { fprintf(o, "timeout\n"); break; }
        cur(ev.dwProcessId);
        switch (ev.dwDebugEventCode) {
        case CREATE_PROCESS_DEBUG_EVENT:
            if (nprocs < 32) { procs[nprocs].pid = ev.dwProcessId; procs[nprocs++].h = ev.u.CreateProcessInfo.hProcess; }
            cur(ev.dwProcessId); { char nm[MAX_PATH] = "?"; snap_mods(); if (nmods) lstrcpynA(nm, mods[0].name, MAX_PATH); fprintf(o, "process %08lx started (%s)\n", ev.dwProcessId, nm); }
            if (nth < 64) { threads[nth] = ev.u.CreateProcessInfo.hThread; tids[nth++] = ev.dwThreadId; } break;
        case CREATE_THREAD_DEBUG_EVENT:
            if (nth < 64) { threads[nth] = ev.u.CreateThread.hThread; tids[nth++] = ev.dwThreadId; }
            fprintf(o, "thread %08lx start %08lx\n", ev.dwThreadId, (DWORD)ev.u.CreateThread.lpStartAddress); break;
        case EXIT_THREAD_DEBUG_EVENT: fprintf(o, "thread %08lx exit %lu\n", ev.dwThreadId, ev.u.ExitThread.dwExitCode); break;
        case LOAD_DLL_DEBUG_EVENT: {
            DWORD off; const char *m; snap_mods(); m = where((DWORD)ev.u.LoadDll.lpBaseOfDll, &off);
            fprintf(o, "load %08lx %s\n", (DWORD)ev.u.LoadDll.lpBaseOfDll, m ? m : "?");
            if (ev.u.LoadDll.hFile) CloseHandle(ev.u.LoadDll.hFile);
            break; }
        case OUTPUT_DEBUG_STRING_EVENT: {
            char b[1024]; DWORD n = ev.u.DebugString.nDebugStringLength; if (n > 1023) n = 1023; memset(b, 0, sizeof(b));
            if (ev.u.DebugString.fUnicode) { WCHAR wb[1024]; memset(wb, 0, sizeof(wb)); rd((DWORD)ev.u.DebugString.lpDebugStringData, wb, n * 2); WideCharToMultiByte(CP_ACP, 0, wb, -1, b, 1023, NULL, NULL); }
            else rd((DWORD)ev.u.DebugString.lpDebugStringData, b, n);
            fprintf(o, "ods: %s%s", b, (n && b[strlen(b) - 1] == '\n') ? "" : "\n"); break; }
        case EXCEPTION_DEBUG_EVENT: {
            EXCEPTION_RECORD *er = &ev.u.Exception.ExceptionRecord; DWORD off, k; const char *m; CONTEXT c; HANDLE th = NULL;
            nex++;
            if (er->ExceptionCode == EXCEPTION_BREAKPOINT && ev.u.Exception.dwFirstChance) { fprintf(o, "breakpoint (process %08lx)\n", ev.dwProcessId); break; }
            if (nex > 300) { cont = DBG_EXCEPTION_NOT_HANDLED; break; }
            snap_mods(); m = where((DWORD)er->ExceptionAddress, &off);
            fprintf(o, "EXCEPTION %08lx %s-chance at %08lx (%s+%lx) thread %08lx params", er->ExceptionCode, ev.u.Exception.dwFirstChance ? "first" : "SECOND",
                    (DWORD)er->ExceptionAddress, m ? m : "?", m ? off : 0, ev.dwThreadId);
            for (k = 0; k < er->NumberParameters && k < 6; k++) fprintf(o, " %08lx", er->ExceptionInformation[k]);
            fprintf(o, "\n");
            if (er->ExceptionCode == 0xE06D7363 && er->NumberParameters >= 3) cxx(er->ExceptionInformation[2]);
            for (i = 0; i < nth; i++) if (tids[i] == ev.dwThreadId) th = threads[i];
            c.ContextFlags = CONTEXT_FULL;
            if (th && GetThreadContext(th, &c)) {
                DWORD st[96], j;
                fprintf(o, "    eax %08lx ebx %08lx ecx %08lx edx %08lx esi %08lx edi %08lx ebp %08lx esp %08lx eip %08lx\n",
                        c.Eax, c.Ebx, c.Ecx, c.Edx, c.Esi, c.Edi, c.Ebp, c.Esp, c.Eip);
                if (rd(c.Esp, st, sizeof(st))) for (j = 0; j < 96; j++) { m = where(st[j], &off); if (m && strcmp(m, "KERNEL32(9x)")) fprintf(o, "    stack+%03lx %08lx %s+%lx\n", j * 4, st[j], m, off); }
                if (er->ExceptionCode == 0xE06D7363) {   /* strings near the thrown object */
                    DWORD obj[8]; if (rd(er->ExceptionInformation[1], obj, 32)) { fprintf(o, "    object:"); for (j = 0; j < 8; j++) fprintf(o, " %08lx", obj[j]); fprintf(o, "\n"); for (j = 0; j < 8; j++) if (obj[j] > 0x10000) ascii_at(obj[j]); }
                }
            }
            fflush(o);
            if (er->ExceptionCode != EXCEPTION_BREAKPOINT) cont = DBG_EXCEPTION_NOT_HANDLED;
            break; }
        case EXIT_PROCESS_DEBUG_EVENT:
            fprintf(o, "process %08lx exit code %08lx\n", ev.dwProcessId, ev.u.ExitProcess.dwExitCode);
            if (ev.dwProcessId == pi.dwProcessId || !follow) { fclose(o); return 0; }
            break;
        }
        fflush(o);
        ContinueDebugEvent(ev.dwProcessId, ev.dwThreadId, cont);
    }
    fclose(o); return 0;
}
