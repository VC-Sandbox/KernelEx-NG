/* sample.c - SAMPLE.EXE <pid hex> <samples> <ms> <log>: samples every thread of a running process (suspend,
 * GetThreadContext, read the stack, resume) and logs EIP + return addresses that fall in modules, mapped to
 * module+offset; a summary of the most frequent EIP locations at the end. Built as an NT 5.1 program so that
 * KernelEx supplies OpenThread (Windows 98 has none). The process keeps running. */
#include <windows.h>
#include <tlhelp32.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
typedef HANDLE (WINAPI *T_OT)(DWORD, BOOL, DWORD);
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
typedef struct { char key[96]; int n; } HIT;
static HIT hits[512]; static int nh;
static void hit(const char *k) { int i; for (i = 0; i < nh; i++) if (!strcmp(hits[i].key, k)) { hits[i].n++; return; } if (nh < 512) { lstrcpynA(hits[nh].key, k, 96); hits[nh++].n = 1; } }
int main(int argc, char **argv)
{
    T_OT ot = (T_OT)GetProcAddress(GetModuleHandleA("KERNEL32.DLL"), "OpenThread");
    int ns, ms, s, i, j;
    if (argc < 5) return 1;
    pid = strtoul(argv[1], NULL, 16); ns = atoi(argv[2]); ms = atoi(argv[3]); o = fopen(argv[4], "w");
    if (!o) return 2;
    if (!ot) { fprintf(o, "no OpenThread\n"); return 3; }
    hp = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
    if (!hp) { fprintf(o, "OpenProcess %lu\n", GetLastError()); return 4; }
    snap_mods();
    for (s = 0; s < ns; s++) {
        HANDLE ts = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0); THREADENTRY32 te; te.dwSize = sizeof(te);
        if (Thread32First(ts, &te)) do {
            HANDLE th; CONTEXT c; DWORD st[128], got = 0, off; const char *m; char key[96];
            if (te.th32OwnerProcessID != pid) continue;
            th = ot(THREAD_ALL_ACCESS, FALSE, te.th32ThreadID);
            if (!th) { fprintf(o, "  OpenThread %08lx failed %lu\n", te.th32ThreadID, GetLastError()); continue; }
            SuspendThread(th);
            c.ContextFlags = CONTEXT_FULL;
            if (GetThreadContext(th, &c)) {
                ReadProcessMemory(hp, (LPCVOID)c.Esp, st, sizeof(st), &got);
                ResumeThread(th);
                m = where(c.Eip, &off);
                if (m) sprintf(key, "%08lx %s+%lx", te.th32ThreadID, m, off); else sprintf(key, "%08lx %08lx", te.th32ThreadID, c.Eip);
                hit(key);
                fprintf(o, "s%d t%08lx eip %s |", s, te.th32ThreadID, key + 9);
                for (j = 0, i = 0; j < (int)(got / 4) && i < 14; j++) { m = where(st[j], &off); if (m) { fprintf(o, " %s+%lx", m, off); i++; } }
                fprintf(o, "\n");
                { int kx = 0; DWORD q; for (j = 0; j < (int)(got / 4) && j < 40; j++) { const char *mm = where(st[j], &q); if (mm && !strcmp(mm, "KEXNT.DLL")) kx = 1; } if (kx) { fprintf(o, "    raw:"); for (j = 0; j < 40 && j < (int)(got / 4); j++) fprintf(o, " %08lx", st[j]); fprintf(o, "\n    regs eax %08lx ebx %08lx ecx %08lx edx %08lx esi %08lx edi %08lx ebp %08lx\n", c.Eax, c.Ebx, c.Ecx, c.Edx, c.Esi, c.Edi, c.Ebp); } }
            } else ResumeThread(th);
            CloseHandle(th);
        } while (Thread32Next(ts, &te));
        CloseHandle(ts); fflush(o);
        Sleep(ms);
    }
    fprintf(o, "summary:\n");
    for (i = 0; i < nh; i++) fprintf(o, "%4d %s\n", hits[i].n, hits[i].key);
    fclose(o); return 0;
}
